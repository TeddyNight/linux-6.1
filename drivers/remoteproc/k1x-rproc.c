// SPDX-License-Identifier: GPL-2.0

#include <linux/limits.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/regmap.h>
#include <linux/mfd/syscon.h>
#include <linux/of_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/pm_runtime.h>
#include <linux/remoteproc.h>
#include <linux/reset.h>
#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/kthread.h>
#include <linux/clk-provider.h>
#include <linux/mailbox_client.h>
#include <linux/completion.h>
#include <linux/freezer.h>
#include <uapi/linux/sched/types.h>
#include <uapi/linux/sched.h>
#include <linux/sched/prio.h>
#include <linux/rpmsg.h>
#include <linux/pm_qos.h>
#include <linux/delay.h>
#include <linux/syscore_ops.h>
#include <linux/pm_domain.h>
#include <linux/spacemit/platform_pm_ops.h>
#include "remoteproc_internal.h"

#define MAX_MEM_BASE	2
#define MAX_MBOX	2

#define K1X_MBOX_VQ0_ID	0
#define K1X_MBOX_VQ1_ID	1

#define BOOTC_MEM_BASE_OFFSET	0
#define SYSCTRL_MEM_BASE_OFFSET	1

#define ESOS_BOOT_ENTRY_REG_OFFSET	0x88
#define ESOS_BOOTUP_REG_OFFSET		0x30
#define ESOS_AON_PER_CLK_RST_CTL_REG	0x2c

#define ESOS_DDR_REGMAP_BASE_REG_OFFSET	0xc0

#define APMU_AUDIO_CLK_RES_CTRL	0x14c
#define APMU_AUDIO_POWER_STATUS_OFFSET	23

#define DEV_PM_QOS_CLK_GATE            1
#define DEV_PM_QOS_REGULATOR_GATE      2
#define DEV_PM_QOS_PM_DOMAIN_GATE      4
#define DEV_PM_QOS_DEFAULT             7

struct dev_pm_qos_request greq;
struct reset_control *gcore_reset;

struct spacemit_mbox {
	const char name[10];
	struct mbox_chan *chan;
	struct mbox_client client;
	struct task_struct *mb_thread;
	bool kthread_running;
	struct completion mb_comp;
	int vq_id;
};

struct spacemit_rproc {
	struct device *dev;
	struct reset_control *core_rst;
	struct clk *core_clk;
	unsigned int ddr_remap_base;
	void __iomem *base[MAX_MEM_BASE];
	struct spacemit_mbox *mb;
#ifdef CONFIG_PM_SLEEP
	struct rpmsg_device *rpdev;
#endif
};

static int spacemit_rproc_mem_alloc(struct rproc *rproc,
				 struct rproc_mem_entry *mem)
{
	void __iomem *va = NULL;

	dev_dbg(&rproc->dev, "map memory: %pa+%zx\n", &mem->dma, mem->len);
	va = ioremap(mem->dma, mem->len);
	if (!va) {
		dev_err(&rproc->dev, "Unable to map memory region: %pa+%zx\n",
			&mem->dma, mem->len);
		return -ENOMEM;
	}

	memset(va, 0, mem->len);

	/* Update memory entry va */
	mem->va = va;

	return 0;
}

static int spacemit_rproc_mem_release(struct rproc *rproc,
				   struct rproc_mem_entry *mem)
{
	dev_dbg(&rproc->dev, "unmap memory: %pa\n", &mem->dma);

	iounmap(mem->va);

	return 0;
}

static int spacemit_rproc_prepare(struct rproc *rproc)
{
	struct spacemit_rproc *priv = rproc->priv;
	struct device *dev = rproc->dev.parent;
	struct device_node *np = dev->of_node;
	struct of_phandle_iterator it;
	struct rproc_mem_entry *mem;
	struct reserved_mem *rmem;
	u32 da;
	int ret, index = 0;

	/* de-assert the audio module */
	reset_control_deassert(priv->core_rst);

	/* open the clk & pm-switch using pm-domain framework */
	dev_pm_qos_add_request(priv->dev, &greq, DEV_PM_QOS_MAX_FREQUENCY,
			DEV_PM_QOS_CLK_GATE | DEV_PM_QOS_PM_DOMAIN_GATE);

	/* enable the power-switch and the clk */
	pm_runtime_get_sync(priv->dev);

	/* Register associated reserved memory regions */
	of_phandle_iterator_init(&it, np, "memory-region", NULL, 0);
	while (of_phandle_iterator_next(&it) == 0) {
		rmem = of_reserved_mem_lookup(it.node);
		if (!rmem) {
			dev_err(&rproc->dev,
				"unable to acquire memory-region\n");
			return -EINVAL;
		}

		if (rmem->base > U64_MAX) {
			dev_err(&rproc->dev,
				"the rmem base is overflow\n");
			return -EINVAL;
		}

		/* find the da */
		ret = of_property_read_u32(it.node, "da_base", &da);
		if (ret) {
			/* no da_base; means that the da = dma */
			da = rmem->base;
		}

		if (strcmp(it.node->name, "vdev0buffer")) {
			mem = rproc_mem_entry_init(dev, NULL,
						   rmem->base,
						   rmem->size, da,
						   spacemit_rproc_mem_alloc,
						   spacemit_rproc_mem_release,
						   it.node->name);
		} else {
			/* Register reserved memory for vdev buffer alloc */
			mem = rproc_of_resm_mem_entry_init(dev, index,
							   rmem->size,
							   rmem->base,
							   it.node->name);
		}

		if (!mem)
			return -ENOMEM;

		rproc_add_carveout(rproc, mem);
		index++;
	}

	return 0;
}

static int spacemit_rproc_start(struct rproc *rproc)
{
	struct spacemit_rproc *priv = rproc->priv;

	/* enable ipc2ap clk & reset--> rcpu side */
	writel(0xff, priv->base[BOOTC_MEM_BASE_OFFSET] + ESOS_AON_PER_CLK_RST_CTL_REG);

	/* set the boot-entry */
	writel(rproc->bootaddr, priv->base[SYSCTRL_MEM_BASE_OFFSET] + ESOS_BOOT_ENTRY_REG_OFFSET);

	/* set ddr map */
	writel(priv->ddr_remap_base, priv->base[SYSCTRL_MEM_BASE_OFFSET] + ESOS_DDR_REGMAP_BASE_REG_OFFSET);

	/* lanching up esos */
	writel(1, priv->base[BOOTC_MEM_BASE_OFFSET] + ESOS_BOOTUP_REG_OFFSET);

	return 0;
}

static int spacemit_rproc_stop(struct rproc *rproc)
{
	struct spacemit_rproc *priv = rproc->priv;

	/* hold the rcpu */
	writel(0, priv->base[BOOTC_MEM_BASE_OFFSET] + ESOS_BOOTUP_REG_OFFSET);

	pm_runtime_put_sync(priv->dev);

	reset_control_assert(priv->core_rst);

	return 0;
}

static int spacemit_rproc_parse_fw(struct rproc *rproc, const struct firmware *fw)
{
	int ret;

	ret = rproc_elf_load_rsc_table(rproc, fw);
	if (ret)
		dev_info(&rproc->dev, "No resource table in elf\n");

	return 0;
}

static u64 spacemit_get_boot_addr(struct rproc *rproc, const struct firmware *fw)
{
	int err;
	unsigned int entry_point;
	struct device *dev = rproc->dev.parent;

	/* get the entry point */
	err = of_property_read_u32(dev->of_node, "esos-entry-point", &entry_point);
	if (err) {
		 dev_err(dev, "failed to get entry point\n");
		 return 0;
	}

	return entry_point;
}

static void spacemit_rproc_kick(struct rproc *rproc, int vqid)
{
	struct spacemit_rproc *ddata = rproc->priv;
	unsigned int i;
	int err;

	if (WARN_ON(vqid >= MAX_MBOX))
		return;

	for (i = 0; i < MAX_MBOX; i++) {
		if (vqid != ddata->mb[i].vq_id)
			continue;
		if (!ddata->mb[i].chan)
			return;
		err = mbox_send_message(ddata->mb[i].chan, "kick");
		if (err < 0)
			dev_err(&rproc->dev, "%s: failed (%s, err:%d)\n",
				__func__, ddata->mb[i].name, err);
		return;
	}
}

static struct rproc_ops spacemit_rproc_ops = {
	.prepare	= spacemit_rproc_prepare,
	.start		= spacemit_rproc_start,
	.stop		= spacemit_rproc_stop,
	.load		= rproc_elf_load_segments,
	.parse_fw	= spacemit_rproc_parse_fw,
	.kick		= spacemit_rproc_kick,
	.find_loaded_rsc_table = rproc_elf_find_loaded_rsc_table,
	.sanity_check	= rproc_elf_sanity_check,
	.get_boot_addr	= spacemit_get_boot_addr,
};

static int __process_theread(void *arg)
{
	int ret;
	struct mbox_client *cl = arg;
	struct rproc *rproc = dev_get_drvdata(cl->dev);
	struct spacemit_mbox *mb = container_of(cl, struct spacemit_mbox, client);
	struct sched_param param = {.sched_priority = 0 };

	mb->kthread_running = true;
	ret = sched_setscheduler(current, SCHED_FIFO, &param);

	do {
		wait_for_completion_timeout(&mb->mb_comp, 10);
		if (rproc_vq_interrupt(rproc, mb->vq_id) == IRQ_NONE)
			dev_dbg(&rproc->dev, "no message found in vq%d\n", mb->vq_id);
	} while (!kthread_should_stop());

	mb->kthread_running = false;

	return 0;
}
static void k1x_rproc_mb_callback(struct mbox_client *cl, void *data)
{
	struct spacemit_mbox *mb = container_of(cl, struct spacemit_mbox, client);

	complete(&mb->mb_comp);
}

static struct spacemit_mbox k1x_rpoc_mbox[] = {
	{
		.name = "vq0",
		.vq_id = K1X_MBOX_VQ0_ID,
		.client = {
			.rx_callback = k1x_rproc_mb_callback,
			.tx_block = true,
		},
	},
	{
		.name = "vq1",
		.vq_id = K1X_MBOX_VQ1_ID,
		.client = {
			.rx_callback = k1x_rproc_mb_callback,
			.tx_block = true,
		},
	},
};

#ifdef CONFIG_PM_SLEEP

#define STARTUP_MSG "pwr_management"

static struct rpmsg_device_id rpmsg_rcpu_pwr_management_id_table[] = {
	{ .name	= "rcpu-pwr-management-service", .driver_data = 0 },
	{ },
};
MODULE_DEVICE_TABLE(rpmsg, rpmsg_rcpu_pwr_management_id_table);

static int rpmsg_rcpu_pwr_cb(struct rpmsg_device *rpdev, void *data,
		int len, void *priv, u32 src)
{
	struct spacemit_rproc *srproc;

	if (strcmp(data, "pwr_management_ok") == 0) {
		pr_err("Connection create success\n");
		return 0;
	}

	srproc = dev_get_drvdata(&rpdev->dev);

	/* do something */

	return 0;
}

static int rpmsg_rcpu_pwr_manage_probe(struct rpmsg_device *rpdev)
{
	int ret;
	struct rproc *rproc;
	struct spacemit_rproc *srproc;
	struct platform_device *pdev;

	pdev = (struct platform_device *)rpmsg_rcpu_pwr_management_id_table[0].driver_data;

	rproc = platform_get_drvdata(pdev);
	srproc = rproc->priv;
	srproc->rpdev = rpdev;

	dev_set_drvdata(&rpdev->dev, srproc);

	dev_info(&rpdev->dev, "new channel: 0x%x -> 0x%x!\n",
					rpdev->src, rpdev->dst);

	ret = rpmsg_send(rpdev->ept, STARTUP_MSG, strlen(STARTUP_MSG));

	return 0;
}

static void rpmsg_rcpu_pwr_manage_romove(struct rpmsg_device *rpdev)
{
	dev_info(&rpdev->dev, "rpmsg rcpu power management driver is removed\n");
}

/* here we should register a endpoint for power-management */
static struct rpmsg_driver rpmsg_rcpu_pm_client = {
	.drv.name	= KBUILD_MODNAME,
	.id_table	= rpmsg_rcpu_pwr_management_id_table,
	.probe		= rpmsg_rcpu_pwr_manage_probe,
	.callback	= rpmsg_rcpu_pwr_cb,
	.remove		= rpmsg_rcpu_pwr_manage_romove,
};

module_rpmsg_driver(rpmsg_rcpu_pm_client);

static int rproc_syscore_suspend(void)
{
	return 0;
}

static void rproc_syscore_resume(void)
{
	/* reset the rcpu */
	reset_control_assert(gcore_reset);

	reset_control_deassert(gcore_reset);
}

static struct syscore_ops rproc_syscore_ops = {
	.suspend = rproc_syscore_suspend,
	.resume = rproc_syscore_resume,
};

#define RCPU_ENTER_LOW_PWR_MODE		"$"

static int rproc_platform_late(void)
{
	int ret;
	unsigned int val;
	struct rproc *rproc;
	struct spacemit_rproc *srproc;
	struct rproc_mem_entry *rcpu_snapshots_mem;
	struct platform_device *pdev;
	struct generic_pm_domain *genpd;

	pdev = (struct platform_device *)rpmsg_rcpu_pwr_management_id_table[0].driver_data;

	rproc = dev_get_drvdata(&pdev->dev);
	srproc = rproc->priv;

	/* send msg to rcpu to let it enter low power mode */
	ret = rpmsg_send(srproc->rpdev->ept, RCPU_ENTER_LOW_PWR_MODE,
			strlen(RCPU_ENTER_LOW_PWR_MODE));

	rcpu_snapshots_mem = rproc_find_carveout_by_name(rproc, "rcpu_mem_snapshots");
	if (!rcpu_snapshots_mem) {
		pr_err("Failed to find the rcpu_mem_snapshots\n");
		return -1;
	}

	while (1) {
		/* will be wrotten by rpcu */
		val = readl(rcpu_snapshots_mem->va);
		if (val == 1)
			break;
	}

	/* wait the rcpu enter wfi */
	mdelay(10);

	genpd = pd_to_genpd(pdev->dev.pm_domain);

	pdev->dev.power.wakeup_path = false;

	/* close the clk & power-switch */
	genpd->domain.ops.suspend_noirq(&pdev->dev);

	return 0;
}

static void rproc_platfrom_wake(void)
{
	unsigned int val;
	struct rproc *rproc;
	struct spacemit_rproc *srproc;
	struct rproc_mem_entry *rcpu_sram_mem, *rcpu_snapshots_mem;
	struct platform_device *pdev;
	struct generic_pm_domain *genpd;

	pdev = (struct platform_device *)rpmsg_rcpu_pwr_management_id_table[0].driver_data;

	rproc = dev_get_drvdata(&pdev->dev);
	srproc = rproc->priv;

	genpd = pd_to_genpd(pdev->dev.pm_domain);
	/* enable the clk & power-switch */
	genpd->domain.ops.resume_noirq(&pdev->dev);

	/* enable ipc2ap clk & reset--> rcpu side */
	writel(0xff, srproc->base[BOOTC_MEM_BASE_OFFSET] + ESOS_AON_PER_CLK_RST_CTL_REG);

	/* set ddr map */
	writel(srproc->ddr_remap_base, srproc->base[SYSCTRL_MEM_BASE_OFFSET] + ESOS_DDR_REGMAP_BASE_REG_OFFSET);

	rcpu_sram_mem = rproc_find_carveout_by_name(rproc, "mem");
	if (!rcpu_sram_mem) {
		pr_err("Failed to find the rcpu_mem_0\n");
		return;
	}

	rcpu_snapshots_mem = rproc_find_carveout_by_name(rproc, "rcpu_mem_snapshots");
	if (!rcpu_snapshots_mem) {
		pr_err("Failed to find the rcpu_mem_snapshots\n");
		return;
	}

	/* copy the code */
	memcpy((void *)rcpu_sram_mem->va,
			(void *)((u32 *)rcpu_snapshots_mem->va + 1),
			rcpu_sram_mem->len - sizeof(u32));

	/* luaching up rpcu */	
	writel(1, srproc->base[BOOTC_MEM_BASE_OFFSET] + ESOS_BOOTUP_REG_OFFSET);
	
	while (1) {
		/* will be wrotten by rpcu */
		val = readl(rcpu_snapshots_mem->va);
		if (val == 2)
			break;
	}

	memset((void *)rcpu_snapshots_mem->va, 0, rcpu_snapshots_mem->len);
}

static struct platfrom_pm_ops rproc_platform_pm_ops = {
	.prepare_late = rproc_platform_late,
	.wake = rproc_platfrom_wake,
};

static int spacemit_rproc_suspend(struct device *dev)
{
	/* this code do nothing but pretect the power & clk of audio 
	 * from closing in noirq process when system suspend
	 * */
	device_set_wakeup_path(dev);

	return 0;
}

static int spacemit_rproc_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops spacemit_rproc_pm_ops = {
	.suspend = spacemit_rproc_suspend,
	.resume = spacemit_rproc_resume,
};
#endif

static int spacemit_rproc_probe(struct platform_device *pdev)
{
	int ret, i;
	const char *name;
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	const char *fw_name = "esos.elf";
	struct spacemit_rproc *priv;
	struct mbox_client *cl;
	struct rproc *rproc;

	ret = rproc_of_parse_firmware(dev, 0, &fw_name);
	if (ret < 0 && ret != -EINVAL)
		return ret;

	rproc = devm_rproc_alloc(dev, np->name, &spacemit_rproc_ops,
				fw_name, sizeof(*priv));
	if (!rproc)
		return -ENOMEM;

	priv = rproc->priv;
	priv->dev = dev;

	priv->base[BOOTC_MEM_BASE_OFFSET] = devm_platform_ioremap_resource(pdev, BOOTC_MEM_BASE_OFFSET);
	if (IS_ERR(priv->base[BOOTC_MEM_BASE_OFFSET])) {
		ret = PTR_ERR(priv->base[BOOTC_MEM_BASE_OFFSET]);
		dev_err(dev, "failed to get reg base\n");
		return ret;
	}

	priv->base[SYSCTRL_MEM_BASE_OFFSET] = devm_platform_ioremap_resource(pdev, SYSCTRL_MEM_BASE_OFFSET);
	if (IS_ERR(priv->base[SYSCTRL_MEM_BASE_OFFSET])) {
		ret = PTR_ERR(priv->base[SYSCTRL_MEM_BASE_OFFSET]);
		dev_err(dev, "failed to get reg base\n");
		return ret;
	}

	priv->core_rst = devm_reset_control_get_exclusive(dev, NULL);
	if (IS_ERR(priv->core_rst)) {
		ret = PTR_ERR(priv->core_rst);
		dev_err_probe(dev, ret, "fail to acquire rproc reset\n");
		return ret;
	}

	gcore_reset = priv->core_rst;

	priv->core_clk = devm_clk_get(dev, "core");
	if (IS_ERR(priv->core_clk)) {
		ret = PTR_ERR(priv->core_clk);
		dev_err(dev, "failed to acquire rpoc core\n");
		return ret;
	}

	/* get the ddr-remap base */
	ret = of_property_read_u32(pdev->dev.of_node, "ddr-remap-base", &priv->ddr_remap_base);

	pm_runtime_enable(dev);

	platform_set_drvdata(pdev, rproc);

	/* get the mailbox */
	priv->mb = k1x_rpoc_mbox;

	for (i = 0; i < MAX_MBOX; ++i) {
		name = priv->mb[i].name;

		cl = &priv->mb[i].client;
		cl->dev = dev;
		init_completion(&priv->mb[i].mb_comp);

		priv->mb[i].chan = mbox_request_channel_byname(cl, name);
		if (IS_ERR(priv->mb[i].chan)) {
			dev_err(dev, "failed to request mbox channel\n");
			return -EINVAL;
		}

		if (priv->mb[i].vq_id >= 0) {
			priv->mb[i].mb_thread = kthread_run(__process_theread, (void *)cl, name);
			if (IS_ERR(priv->mb[i].mb_thread))
				return PTR_ERR(priv->mb[i].mb_thread);
		}
	}

#ifdef CONFIG_PM_SLEEP
	rpmsg_rcpu_pwr_management_id_table[0].driver_data = (unsigned long long)pdev;

	register_syscore_ops(&rproc_syscore_ops);

	register_platform_pm_ops(&rproc_platform_pm_ops);
#endif

	ret = devm_rproc_add(dev, rproc);
	if (ret) {
		dev_err(dev, "rproc_add failed\n");
	}

	ret = rproc_boot(rproc);
	if (ret) {
		dev_err(dev, "rproc_boot failed\n");
	}

	return ret;
}

static void k1x_rproc_free_mbox(struct rproc *rproc)
{
	struct spacemit_rproc *ddata = rproc->priv;
	unsigned int i;

	for (i = 0; i < MAX_MBOX; i++) {
		if (ddata->mb[i].chan)
			mbox_free_channel(ddata->mb[i].chan);
		ddata->mb[i].chan = NULL;
	}
}

static int spacemit_rproc_remove(struct platform_device *pdev)
{
	int i = 0;
	struct rproc *rproc = platform_get_drvdata(pdev);
	struct spacemit_rproc *ddata = rproc->priv;

	for (i = 0; i < MAX_MBOX; ++i)
		if (ddata->mb[i].kthread_running)
			kthread_stop(ddata->mb[i].mb_thread);

	rproc_del(rproc);
	k1x_rproc_free_mbox(rproc);
	rproc_free(rproc);

#ifdef CONFIG_PM_SLEEP
	unregister_rpmsg_driver(&rpmsg_rcpu_pm_client);
	unregister_platform_pm_ops(&rproc_platform_pm_ops);
#endif
	return 0;
}

static const struct of_device_id spacemit_rproc_of_match[] = {
	{ .compatible = "spacemit,k1-x-rproc" },
	{},
};

MODULE_DEVICE_TABLE(of, spacemit_rproc_of_match);

static void spacemit_rproc_shutdown(struct platform_device *pdev)
{
	int i;
	struct rproc *rproc;
	struct spacemit_rproc *priv;

	rproc = dev_get_drvdata(&pdev->dev);
	priv = rproc->priv;

	for (i = 0; i < MAX_MBOX; ++i) {
		/* release the resource of rt thread */
		kthread_stop(priv->mb[i].mb_thread);
		/* mbox_free_channel(priv->mb[i].chan); */
	}
}

static struct platform_driver spacemit_rproc_driver = {
	.probe = spacemit_rproc_probe,
	.remove = spacemit_rproc_remove,
	.shutdown = spacemit_rproc_shutdown,
	.driver = {
		.name = "spacemit-rproc",
#ifdef CONFIG_PM_SLEEP
		.pm	= &spacemit_rproc_pm_ops,
#endif
		.of_match_table = spacemit_rproc_of_match,
	},
};

static __init int spacemit_rproc_driver_init(void)
{
	return platform_driver_register(&spacemit_rproc_driver);
}
device_initcall(spacemit_rproc_driver_init);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("sapcemit remote processor control driver");

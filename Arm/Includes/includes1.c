#include "Backship.c"

static int __init nios2_soc_device_init(void)
{
	struct soc_device *soc_dev;
	struct soc_device_attribute *soc_dev_attr;
	const char *machine;

	soc_dev_attr = kzalloc(sizeof(*soc_dev_attr), GFP_KERNEL);
	if (soc_dev_attr) {
		machine = of_flat_dt_get_machine_name();
		if (machine)
			soc_dev_attr->machine = kasprintf(GFP_KERNEL, "%s",
						machine);

		soc_dev_attr->family = "Nios II";

		soc_dev = soc_device_register(soc_dev_attr);
		if (IS_ERR(soc_dev)) {
			kfree(soc_dev_attr->machine);
			kfree(soc_dev_attr);
		}
	}

	return 0;
}

device_initcall(nios2_soc_device_init);

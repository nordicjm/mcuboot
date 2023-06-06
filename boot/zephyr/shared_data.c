/*
 * Copyright (c) 2023, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <zephyr/kernel.h>
#include <zephyr/devicetree.h>
#include <zephyr/retention/retention.h>
#include <zephyr/logging/log.h>
#include <app_version.h>
#include <bootutil/boot_record.h>
#include <bootutil/boot_status.h>
#include <../../bootutil/src/bootutil_priv.h>

#define SHARED_MEMORY_MIN_SIZE 8

LOG_MODULE_REGISTER(bootloader_config, CONFIG_RETENTION_LOG_LEVEL);

static bool shared_memory_init_done = false;
static uint16_t shared_data_size = SHARED_DATA_HEADER_SIZE;
static ssize_t shared_data_max_size = 0;
static const struct device *bootloader_config_dev =
                                    DEVICE_DT_GET(DT_CHOSEN(zephyr_bootloader_config));

BUILD_ASSERT(SHARED_MEMORY_MIN_SIZE < \
             DT_REG_SIZE_BY_IDX(DT_CHOSEN(zephyr_bootloader_config), 0), \
             "zephyr,bootloader-config area is too small for bootloader configuration struct");

int boot_add_data_to_shared_area(uint8_t        major_type,
                                 uint16_t       minor_type,
                                 size_t         size,
                                 const uint8_t *data)
{
    struct shared_data_tlv_header header = {
        .tlv_magic = SHARED_DATA_TLV_INFO_MAGIC,
        .tlv_tot_len = shared_data_size,
    };
    struct shared_data_tlv_entry tlv_entry = {0};
    uint16_t boot_data_size;
    uintptr_t tlv_end, offset;
    int rc;

    if (data == NULL) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Check whether first time to call this function. If does then initialise
     * shared data area.
     */
    if (!shared_memory_init_done) {
        retention_clear(bootloader_config_dev);
        shared_data_max_size = retention_size(bootloader_config_dev);
        shared_memory_init_done = true;
    }

    /* Check whether TLV entry is already added.
     * Get the boundaries of TLV section
     */
    tlv_end = shared_data_size;
    offset  = SHARED_DATA_HEADER_SIZE;

    /* Iterates over the TLV section looks for the same entry if found then
     * returns with error: SHARED_MEMORY_OVERWRITE
     */
    while (offset < tlv_end) {
        /* Create local copy to avoid unaligned access */
        rc = retention_read(bootloader_config_dev, offset, (void *)&tlv_entry,
                            SHARED_DATA_ENTRY_HEADER_SIZE);

        if (rc) {
            return SHARED_MEMORY_READ_ERROR;
        }

        if (GET_MAJOR(tlv_entry.tlv_type) == major_type &&
            GET_MINOR(tlv_entry.tlv_type) == minor_type) {
            return SHARED_MEMORY_OVERWRITE;
        }

        offset += SHARED_DATA_ENTRY_SIZE(tlv_entry.tlv_len);
    }

    /* Add TLV entry */
    tlv_entry.tlv_type = SET_TLV_TYPE(major_type, minor_type);
    tlv_entry.tlv_len  = size;

    if (!boot_u16_safe_add(&boot_data_size, shared_data_size,
                           SHARED_DATA_ENTRY_SIZE(size))) {
        return SHARED_MEMORY_GEN_ERROR;
    }

    /* Verify overflow of shared area */
    if (boot_data_size > shared_data_max_size) {
        return SHARED_MEMORY_OVERFLOW;
    }

    offset = shared_data_size;
    rc = retention_write(bootloader_config_dev, offset, (void*)&tlv_entry,
                         SHARED_DATA_ENTRY_HEADER_SIZE);
    if (rc) {
        LOG_ERR("Shared data TLV header write failed: %d", rc);
        return SHARED_MEMORY_WRITE_ERROR;
    }

    offset += SHARED_DATA_ENTRY_HEADER_SIZE;
    rc = retention_write(bootloader_config_dev, offset, data, size);

    if (rc) {
        LOG_ERR("Shared data TLV data write failed: %d", rc);
        return SHARED_MEMORY_WRITE_ERROR;
    }

    shared_data_size += SHARED_DATA_ENTRY_SIZE(size);
    header.tlv_tot_len = shared_data_size;

    rc = retention_write(bootloader_config_dev, 0, (void *)&header,
                         sizeof(header));

    if (rc) {
        return SHARED_MEMORY_WRITE_ERROR;
    }

    return SHARED_MEMORY_OK;
}

#ifdef CONFIG_BOOT_SHARE_DATA
int boot_save_shared_data(const struct image_header *hdr, const struct flash_area *fap,
                          const uint32_t slot)
{
    int rc;

#if defined(CONFIG_SINGLE_APPLICATION_SLOT)
    uint8_t mode = MCUBOOT_MODE_SINGLE_SLOT;
#elif defined(CONFIG_BOOT_SWAP_USING_SCRATCH)
    uint8_t mode = MCUBOOT_MODE_SWAP_USING_SCRATCH;
#elif defined(CONFIG_BOOT_UPGRADE_ONLY)
    uint8_t mode = MCUBOOT_MODE_UPGRADE_ONLY;
#elif defined(CONFIG_BOOT_SWAP_USING_MOVE)
    uint8_t mode = MCUBOOT_MODE_SWAP_USING_MOVE;
#elif defined(CONFIG_BOOT_DIRECT_XIP)
    uint8_t mode = MCUBOOT_MODE_DIRECT_XIP;
#elif defined(CONFIG_BOOT_RAM_LOAD)
    uint8_t mode = MCUBOOT_MODE_RAM_LOAD;
#else
#error "Unknown mcuboot operating mode"
#endif

#if defined(CONFIG_BOOT_SIGNATURE_TYPE_NONE)
    uint8_t signature_type = MCUBOOT_SIGNATURE_TYPE_NONE;
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_RSA)
    uint8_t signature_type = MCUBOOT_SIGNATURE_TYPE_RSA;
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256)
    uint8_t signature_type = MCUBOOT_SIGNATURE_TYPE_ECDSA_P256;
#elif defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519)
    uint8_t signature_type = MCUBOOT_SIGNATURE_TYPE_ED25519;
#else
#error "Unknown mcuboot signature type"
#endif

#if defined(CONFIG_MCUBOOT_SERIAL)
    uint8_t recovery = MCUBOOT_RECOVERY_MODE_SERIAL_RECOVERY;
#elif defined(CONFIG_BOOT_USB_DFU_GPIO) || defined(CONFIG_BOOT_USB_DFU_WAIT)
    uint8_t recovery = MCUBOOT_RECOVERY_MODE_DFU;
#else
    uint8_t recovery = MCUBOOT_RECOVERY_MODE_NONE;
#endif

    struct image_version mcuboot_version = {
        .iv_major = APP_VERSION_MAJOR,
        .iv_minor = APP_VERSION_MINOR,

#ifdef APP_PATCHLEVEL
        .iv_revision = APP_PATCHLEVEL,
#else
        .iv_revision = 0,
#endif

#ifdef VERSION_TWEAK
        .iv_build_num = VERSION_TWEAK,
#else
        .iv_build_num = 0,
#endif
    };

    /* Write out all fields */
    rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO, BLINFO_MODE,
                                      sizeof(mode), &mode);

    if (!rc) {
        rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO,
                                          BLINFO_SIGNATURE_TYPE,
                                          sizeof(signature_type),
                                          &signature_type);
    }

    if (!rc) {
        rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO,
                                          BLINFO_RECOVERY,
                                          sizeof(recovery), &recovery);
    }

    if (!rc) {
        rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO,
                                          BLINFO_RUNNING_SLOT,
                                          sizeof(slot), (void *)&slot);
    }

    if (!rc) {
        rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO,
                                          BLINFO_BOOTLOADER_VERSION,
                                          sizeof(mcuboot_version),
                                          (void *)&mcuboot_version);
    }

int lolz = swap_size2();

    if (!rc) {
        rc = boot_add_data_to_shared_area(TLV_MAJOR_BLINFO,
                                          BLINFO_MAX_APPLICATION_SIZE,
                                          sizeof(lolz),
                                          (void *)&lolz);
    }

    return rc;
}
#endif

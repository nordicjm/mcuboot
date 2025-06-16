#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "flash_map_backend/flash_map_backend.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/image.h"
#include "../src/bootutil_priv.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/security_cnt.h"
#include "bootutil/boot_record.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/ramload.h"
#include "bootutil/boot_hooks.h"
#include "bootutil/mcuboot_status.h"
#include "mcuboot_config/mcuboot_config.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

#if (BOOT_IMAGE_NUMBER > 1)
#define IMAGES_ITER(x) for ((x) = 0; (x) < BOOT_IMAGE_NUMBER; ++(x))
#else
#define IMAGES_ITER(x)
#endif

static int
boot_read_image_headers(struct boot_loader_state *state, bool require_all,
        struct boot_status *bs)
{
    int rc;
    int i;

    for (i = 0; i < BOOT_NUM_SLOTS; i++) {
BOOT_LOG_ERR("read slot %d", i);
        rc = BOOT_HOOK_CALL(boot_read_image_header_hook, BOOT_HOOK_REGULAR,
                            BOOT_CURR_IMG(state), i, boot_img_hdr(state, i));
        if (rc == BOOT_HOOK_REGULAR)
        {
            rc = boot_read_image_header(state, i, boot_img_hdr(state, i), bs);
        }
        if (rc != 0) {
            /* If `require_all` is set, fail on any single fail, otherwise
             * if at least the first slot's header was read successfully,
             * then the boot loader can attempt a boot.
             *
             * Failure to read any headers is a fatal error.
             */
            if (i > 0 && !require_all) {
                return 0;
            } else {
                return rc;
            }
        }
    }

    return 0;
}

/*
 * Check that this is a valid header.  Valid means that the magic is
 * correct, and that the sizes/offsets are "sane".  Sane means that
 * there is no overflow on the arithmetic, and that the result fits
 * within the flash area we are in. Also check the flags in the image
 * and class the image as invalid if flags for encryption/compression
 * are present but these features are not enabled.
 */
static bool
boot_is_header_valid(const struct image_header *hdr, const struct flash_area *fap,
                     struct boot_loader_state *state)
{
    uint32_t size;

    (void)state;

BOOT_LOG_ERR("header valid? %p, %p, %p", hdr, fap, state);

    if (hdr->ih_magic != IMAGE_MAGIC) {
        return false;
    }

    if (!boot_u32_safe_add(&size, hdr->ih_img_size, hdr->ih_hdr_size)) {
        return false;
    }

#ifdef MCUBOOT_DECOMPRESS_IMAGES
    if (!MUST_DECOMPRESS(fap, BOOT_CURR_IMG(state), hdr)) {
#else
    if (1) {
#endif
        if (!boot_u32_safe_add(&size, size, hdr->ih_protect_tlv_size)) {
            return false;
        }
    }

    if (size >= flash_area_get_size(fap)) {
        return false;
    }

#if !defined(MCUBOOT_ENC_IMAGES)
    if (IS_ENCRYPTED(hdr)) {
        return false;
    }
#else
    if ((hdr->ih_flags & IMAGE_F_ENCRYPTED_AES128) &&
        (hdr->ih_flags & IMAGE_F_ENCRYPTED_AES256))
    {
        return false;
    }
#endif

#if !defined(MCUBOOT_DECOMPRESS_IMAGES)
    if (IS_COMPRESSED(hdr)) {
        return false;
    }
#else
    if ((hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA1) &&
        (hdr->ih_flags & IMAGE_F_COMPRESSED_LZMA2))
    {
        return false;
    }
#endif

    return true;
}

static void
close_all_flash_areas(struct boot_loader_state *state)
{
    uint32_t slot;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
#if MCUBOOT_SWAP_USING_SCRATCH
        flash_area_close(BOOT_SCRATCH_AREA(state));
#endif
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            flash_area_close(BOOT_IMG_AREA(state, BOOT_NUM_SLOTS - 1 - slot));
        }
    }
}

static int
boot_get_slot_usage(struct boot_loader_state *state)
{
    uint32_t slot;
    int fa_id;
    int rc;
    struct image_header *hdr = NULL;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
        /* Open all the slots */
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
BOOT_LOG_ERR("open slot %d", slot);
            fa_id = flash_area_id_from_multi_image_slot(
                                                BOOT_CURR_IMG(state), slot);
            rc = flash_area_open(fa_id, &BOOT_IMG_AREA(state, slot));
            assert(rc == 0);
        }

        /* Attempt to read an image header from each slot. */
        rc = boot_read_image_headers(state, false, NULL);
        if (rc != 0) {
            BOOT_LOG_WRN("Failed reading image headers.");
            return rc;
        }

        /* Check headers in all slots */
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            hdr = boot_img_hdr(state, slot);
BOOT_LOG_ERR("get hdr %d = %p", slot, hdr);

            if (boot_is_header_valid(hdr, BOOT_IMG_AREA(state, slot), state)) {
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = true;
                BOOT_LOG_IMAGE_INFO(slot, hdr);
            } else {
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = false;
                BOOT_LOG_INF("Image %d %s slot: Image not found",
                             BOOT_CURR_IMG(state),
                             (slot == BOOT_PRIMARY_SLOT)
                             ? "Primary" : "Secondary");
            }
        }

        state->slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;
    }

    return 0;
}

/**
 * Fills rsp to indicate how booting should occur.
 *
 * @param  state        Boot loader status information.
 * @param  rsp          boot_rsp struct to fill.
 */
static void
fill_rsp(struct boot_loader_state *state, struct boot_rsp *rsp)
{
    uint32_t active_slot;

#if (BOOT_IMAGE_NUMBER > 1)
    /* Always boot from the first enabled image. */
    BOOT_CURR_IMG(state) = 0;
    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        if (!state->img_mask[BOOT_CURR_IMG(state)]) {
            break;
        }
    }
    /* At least one image must be active, otherwise skip the execution */
    if (BOOT_CURR_IMG(state) >= BOOT_IMAGE_NUMBER) {
        return;
    }
#endif

#if defined(MCUBOOT_DIRECT_XIP) || defined(MCUBOOT_RAM_LOAD)
    active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;
#else
    active_slot = BOOT_PRIMARY_SLOT;
#endif

    rsp->br_flash_dev_id = flash_area_get_device_id(BOOT_IMG_AREA(state, active_slot));
    rsp->br_image_off = boot_img_slot_off(state, active_slot);
    rsp->br_hdr = boot_img_hdr(state, active_slot);
}

/**
 * Check the image dependency whether it is satisfied and modify
 * the swap type if necessary.
 *
 * @param dep               Image dependency which has to be verified.
 *
 * @return                  0 on success; nonzero on failure.
 */
static int
boot_verify_slot_dependency(struct boot_loader_state *state,
                            struct image_dependency *dep)
{
    struct image_version *dep_version;
    size_t dep_slot;
    int rc;

    /* Determine the source of the image which is the subject of
     * the dependency and get it's version. */
#if !defined(MCUBOOT_DIRECT_XIP) && !defined(MCUBOOT_RAM_LOAD)
    uint8_t swap_type = state->swap_type[dep->image_id];
    dep_slot = BOOT_IS_UPGRADE(swap_type) ? BOOT_SECONDARY_SLOT
                                          : BOOT_PRIMARY_SLOT;
#else
    dep_slot = state->slot_usage[dep->image_id].active_slot;
#endif

    dep_version = &state->imgs[dep->image_id][dep_slot].hdr.ih_ver;

    rc = boot_version_cmp(dep_version, &dep->image_min_version);
#if !defined(MCUBOOT_DIRECT_XIP) && !defined(MCUBOOT_RAM_LOAD)
    if (rc < 0) {
        /* Dependency not satisfied.
         * Modify the swap type to decrease the version number of the image
         * (which will be located in the primary slot after the boot process),
         * consequently the number of unsatisfied dependencies will be
         * decreased or remain the same.
         */
        switch (BOOT_SWAP_TYPE(state)) {
        case BOOT_SWAP_TYPE_TEST:
        case BOOT_SWAP_TYPE_PERM:
            BOOT_SWAP_TYPE(state) = BOOT_SWAP_TYPE_NONE;
            break;
        case BOOT_SWAP_TYPE_NONE:
            BOOT_SWAP_TYPE(state) = BOOT_SWAP_TYPE_REVERT;
            break;
        default:
            break;
        }
    } else {
        /* Dependency satisfied. */
        rc = 0;
    }
#else
  if (rc >= 0) {
        /* Dependency satisfied. */
        rc = 0;
    }
#endif

    return rc;
}

/**
 * Checks the dependency of all the active slots. If an image found with
 * invalid or not satisfied dependencies the image is removed from SRAM (in
 * case of MCUBOOT_RAM_LOAD strategy) and its slot is set to unavailable.
 *
 * @param  state        Boot loader status information.
 *
 * @return              0 if dependencies are met; nonzero otherwise.
 */
static int
boot_verify_dependencies(struct boot_loader_state *state)
{
    int rc = -1;
    uint32_t active_slot;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
        active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;
        rc = boot_verify_slot_dependencies(state, active_slot);
        if (rc != 0) {
            /* Dependencies not met or invalid dependencies. */

#ifdef MCUBOOT_RAM_LOAD
            boot_remove_image_from_sram(state);
#endif /* MCUBOOT_RAM_LOAD */

            state->slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
            state->slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;

            return rc;
        }
    }

// here you can check if both images are present in both slots, then read the TLVs and do checking to get e.g. required version from one image and supported version from the other, if they exist then the image is bootable, if not then it needs to check the other slots

    return rc;
}
#endif

#ifdef MCUBOOT_HAVE_LOGGING
/**
 * Prints the state of the loaded images.
 *
 * @param  state        Boot loader status information.
 */
static void
print_loaded_images(struct boot_loader_state *state)
{
    uint32_t active_slot;

    (void)state;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
        active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;

        BOOT_LOG_INF("Image %d loaded from the %s slot",
                     BOOT_CURR_IMG(state),
                     (active_slot == BOOT_PRIMARY_SLOT) ?
                     "primary" : "secondary");
    }
}
#endif

fih_ret boot_go_hook(struct boot_rsp *rsp)
{
        struct boot_loader_state *state;
    int rc;
    FIH_DECLARE(fih_rc, FIH_FAILURE);

                state = boot_get_loader_state();

    rc = boot_get_slot_usage(state);
    if (rc != 0) {
        goto out;
    }

#if (BOOT_IMAGE_NUMBER > 1)
    while (true) {
#endif
        FIH_CALL(boot_load_and_validate_images, fih_rc, state);
        if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto out;
        }

#if (BOOT_IMAGE_NUMBER > 1)
        rc = boot_verify_dependencies(state);
        if (rc != 0) {
            /* Dependency check failed for an image, it has been removed from
             * SRAM in case of MCUBOOT_RAM_LOAD strategy, and set to
             * unavailable. Try to load an image from another slot.
             */
            continue;
        }
        /* Dependency check was successful. */
        break;
    }
#endif

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
#if 0
        rc = boot_update_hw_rollback_protection(state);
        if (rc != 0) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto out;
        }
#endif

#if 0
        rc = boot_add_shared_data(state, (uint8_t)state->slot_usage[BOOT_CURR_IMG(state)].active_slot);
        if (rc != 0) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto out;
        }
#endif
    }

    /* All image loaded successfully. */
#ifdef MCUBOOT_HAVE_LOGGING
    print_loaded_images(state);
#endif

    fill_rsp(state, rsp);

out:
    close_all_flash_areas(state);

    if (rc != 0) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

    FIH_RET(fih_rc);
}

/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 * Copyright (c) 2020 Arm Limited
 * Copyright (c) 2021-2023 Nordic Semiconductor ASA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

void led_init(void);

bool detect_pin(void);

bool detect_pin_reset(void);

bool detect_boot_mode(void);

#ifdef CONFIG_SOC_FAMILY_NRF
#include <helpers/nrfx_reset_reason.h>
#endif

#ifdef CONFIG_SOC_FAMILY_NRF
static inline bool boot_skip_serial_recovery()
{
    uint32_t rr = nrfx_reset_reason_get();

    return !(rr == 0 || (rr & NRFX_RESET_REASON_RESETPIN_MASK));
}
#else
static inline bool boot_skip_serial_recovery()
{
    return false;
}
#endif

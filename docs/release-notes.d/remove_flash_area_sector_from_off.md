- The `flash_area_sector_from_off` function has been removed from
  Zephyr, espressif and simulator builds as it is not referenced
  anywhere in the tree, mynewt still calls this function internally
  so that one has been left.

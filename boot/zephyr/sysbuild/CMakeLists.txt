function(${SYSBUILD_CURRENT_MODULE_NAME}_post_image_cmake)
  cmake_parse_arguments(POST_IMAGE_CMAKE "" "IMAGE" "IMAGES" ${ARGN})

  if(NOT "${POST_IMAGE_CMAKE_IMAGE}" STREQUAL "mcuboot")
    return()
  endif()

  foreach(image ${IMAGES})
    set(app_type)
    get_property(app_type TARGET ${image} PROPERTY APP_TYPE)

    if("${app_type}" STREQUAL "MAIN")
message(WARNING "LOL")
      set_property(TARGET ${image} APPEND_STRING PROPERTY CONFIG "CONFIG_FLASH_LOAD_OVERHEAD_SIZE=0x9000\n")
      return()
    endif()
  endforeach()
endfunction(${SYSBUILD_CURRENT_MODULE_NAME}_post_image_cmake)

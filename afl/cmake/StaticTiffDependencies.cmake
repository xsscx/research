# Resolve dependencies referenced by the pinned static libtiff export before
# iccDEV imports TIFF::tiff. iccJpegDump itself does not use libjpeg; JPEG is
# retained here only for libtiff's JPEG-compression codec.

if(NOT TARGET JPEG::JPEG)
    find_package(JPEG REQUIRED)
endif()

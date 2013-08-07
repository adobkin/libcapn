Name: lib${CAPN_LIB_NAME}
Description: ${PROJECT_NAME}
Version: ${CAPN_VERSION}
Libs: -L${CAPN_INSTALL_PATH_LIB} -l${CAPN_LIB_NAME}
Libs.private: -lopenssl
Cflags: -I${CAPN_INSTALL_PATH_INCLUDES} ${CAPN_C_FLAGS}

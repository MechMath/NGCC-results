set(SIG_REF_CFLAGS
    -std=c99 -Wpedantic -Wall -Wextra -O2
)

foreach(BENCH_FOLDER ${SIG_ALG_FOLDERS})
    sig_parse_folder_name(${BENCH_FOLDER} FAMILY LEVEL)
    sig_dove_variant_dir(${FAMILY} ${SIG_IMPL_SUFFIX} VARIANT_DIR)
    sig_dove_param_set(${LEVEL} DOVE_PARAM)
    set(ALG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${VARIANT_DIR})

    if(NOT IS_DIRECTORY "${ALG_DIR}")
        message(FATAL_ERROR "Variant source directory not found: ${ALG_DIR}")
    endif()

    sig_dove_filter_sources(${ALG_DIR} _srcs)
    if(NOT _srcs)
        message(FATAL_ERROR "No .c sources found in ${ALG_DIR}")
    endif()

    add_library(sigalg_${BENCH_FOLDER} STATIC ${_srcs})
    target_include_directories(sigalg_${BENCH_FOLDER} PUBLIC ${ALG_DIR} ${ALG_DIR}/uov)
    target_compile_options(sigalg_${BENCH_FOLDER} PRIVATE ${SIG_REF_CFLAGS})
    set_target_properties(sigalg_${BENCH_FOLDER} PROPERTIES
        OUTPUT_NAME "sigalg_${BENCH_FOLDER}"
    )
    target_compile_definitions(sigalg_${BENCH_FOLDER} PUBLIC
        ALG_SECURITY_LEVEL=${LEVEL}
        DOVE_PARAM_SET=${DOVE_PARAM}
    )
    target_link_libraries(sigalg_${BENCH_FOLDER} PUBLIC m)
endforeach()

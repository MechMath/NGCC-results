option(PKC_BUILD_KAT "Build KAT generation targets (slow for DOVE512)" OFF)

set(SIG_OPT_CFLAGS
    -O3 -march=x86-64 -mavx2 -mtune=native -flto
    -fomit-frame-pointer -std=c99 -Wpedantic -Wall -Wextra
)

set(SIG_KAT_TARGETS "")

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
    target_compile_options(sigalg_${BENCH_FOLDER} PRIVATE ${SIG_OPT_CFLAGS})
    set_target_properties(sigalg_${BENCH_FOLDER} PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION TRUE
        OUTPUT_NAME "sigalg_${BENCH_FOLDER}"
    )
    target_compile_definitions(sigalg_${BENCH_FOLDER} PUBLIC
        ALG_SECURITY_LEVEL=${LEVEL}
        DOVE_PARAM_SET=${DOVE_PARAM}
    )
    target_link_libraries(sigalg_${BENCH_FOLDER} PUBLIC crypto m)

    if(PKC_BUILD_KAT AND EXISTS ${ALG_DIR}/KAT_SIG.c)
        add_executable(KAT_SIG_${BENCH_FOLDER} ${ALG_DIR}/KAT_SIG.c)
        target_include_directories(KAT_SIG_${BENCH_FOLDER} PRIVATE ${ALG_DIR})
        target_compile_options(KAT_SIG_${BENCH_FOLDER} PRIVATE ${SIG_OPT_CFLAGS} -fno-pie)
        target_compile_definitions(KAT_SIG_${BENCH_FOLDER} PRIVATE DOVE_PARAM_SET=${DOVE_PARAM})
        set_target_properties(KAT_SIG_${BENCH_FOLDER} PROPERTIES
            LINK_FLAGS "-no-pie"
            INTERPROCEDURAL_OPTIMIZATION TRUE
        )
        target_link_libraries(KAT_SIG_${BENCH_FOLDER} PRIVATE sigalg_${BENCH_FOLDER})

        add_custom_target(kat_${BENCH_FOLDER}
            COMMAND KAT_SIG_${BENCH_FOLDER}
            WORKING_DIRECTORY ${ALG_DIR}
            DEPENDS KAT_SIG_${BENCH_FOLDER}
            COMMENT "Generate KAT vectors for ${BENCH_FOLDER} -> ${VARIANT_DIR}/output/"
        )
        list(APPEND SIG_KAT_TARGETS kat_${BENCH_FOLDER})
    endif()
endforeach()

if(SIG_KAT_TARGETS)
    add_custom_target(kat DEPENDS ${SIG_KAT_TARGETS})
endif()

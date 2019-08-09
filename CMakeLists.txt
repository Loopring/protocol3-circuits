cmake_minimum_required(VERSION 3.9)

enable_language(CUDA)

#project(cuda)

#add_compile_options(-std=c++11)
#REMOVE_DEFINITIONS(-fPIC)

add_executable(cuda_prover cuda_prover.cu)

target_link_libraries(cuda_prover prover_reference_functions)
#ADD_DEFINITIONS(-fPIC)

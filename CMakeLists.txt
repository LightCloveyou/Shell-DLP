cmake_minimum_required(VERSION 3.24)
project(PowerShell7Guard LANGUAGES CXX RC)
if(NOT MSVC OR NOT WIN32)
    message(FATAL_ERROR "Build with MSVC and the Windows SDK")
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(/W4 /utf-8)

find_program(DOTNET_EXE dotnet REQUIRED)
find_program(CARGO_EXE cargo REQUIRED)
set(GUARD_AST_DIR "${CMAKE_CURRENT_BINARY_DIR}/ast")
set(GUARD_AST_DLL "${GUARD_AST_DIR}/PowerShell7Guard.Ast.dll")
set(GUARD_AST_SOURCES src/analysis/GuardAst.csproj src/analysis/StructuredValues.cs src/analysis/Parser.cs src/analysis/RunspaceState.cs src/analysis/RuleStore.cs src/analysis/SensitiveRules.cs src/analysis/FileInspection.cs src/analysis/adapters/SendAdapters.cs src/analysis/adapters/NativeTransfers.cs src/analysis/adapters/CurlAdapter.cs src/analysis/adapters/HttpAdapter.cs src/analysis/adapters/ObjectAdapters.cs src/analysis/adapters/ControlFlow.cs src/analysis/adapters/DotNetHttp.cs src/analysis/adapters/FunctionCalls.cs src/analysis/adapters/NcatAdapter.cs src/analysis/adapters/WgetAdapter.cs src/analysis/adapters/ScpAdapter.cs src/analysis/ContentTransforms.cs src/analysis/FlowModels.cs src/analysis/GitProof.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/ReadAdapters.cs src/analysis/adapters/ReadSearch.cs src/analysis/adapters/ReadStructured.cs src/analysis/adapters/NativeReads.cs)
set(GUARD_LOADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/loader")
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/LocalSourceReads.cs src/analysis/adapters/StreamReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/ArchiveReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/NativeFilters.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/NativeTextTools.cs src/analysis/adapters/NativeDumpTools.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/CompressionReads.cs src/analysis/adapters/BzipReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/ExtendedStreamReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/StreamTransfers.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/FsMetadataReads.cs src/analysis/adapters/DirectoryTools.cs src/analysis/adapters/MemberGroupReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/SystemReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/SftpAdapter.cs src/analysis/adapters/WindowsTransfers.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/EnvironmentReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/DataStreamReads.cs)
list(APPEND GUARD_AST_SOURCES src/analysis/adapters/NativeArchiveReads.cs src/analysis/adapters/TarReads.cs src/analysis/adapters/SevenZipReads.cs src/analysis/adapters/LzmaReads.cs)
set(GUARD_LOADER_DLL "${GUARD_LOADER_DIR}/PowerShell7Guard.Loader.dll")
configure_file(src/provider/embedded.rc.in embedded.rc @ONLY)
add_custom_command(OUTPUT "${GUARD_AST_DLL}"
    COMMAND "${CMAKE_COMMAND}" -E env "DOTNET_CLI_HOME=${CMAKE_CURRENT_BINARY_DIR}/dotnet"
        DOTNET_NOLOGO=1 "${DOTNET_EXE}" build "${CMAKE_CURRENT_SOURCE_DIR}/src/analysis/GuardAst.csproj" -c Release
        -o "${GUARD_AST_DIR}" "-p:BaseIntermediateOutputPath=${GUARD_AST_DIR}/obj/" "-p:GuardPolicyRoot=${CMAKE_CURRENT_SOURCE_DIR}" -p:NuGetAudit=false
    COMMAND "${CMAKE_COMMAND}" -E touch "${CMAKE_CURRENT_BINARY_DIR}/embedded.rc"
    DEPENDS ${GUARD_AST_SOURCES} VERBATIM)
add_custom_command(OUTPUT "${GUARD_LOADER_DLL}"
    COMMAND "${CMAKE_COMMAND}" -E env "DOTNET_CLI_HOME=${CMAKE_CURRENT_BINARY_DIR}/dotnet"
        DOTNET_NOLOGO=1 "${DOTNET_EXE}" build "${CMAKE_CURRENT_SOURCE_DIR}/src/loader/GuardLoader.csproj" -c Release
        -o "${GUARD_LOADER_DIR}" "-p:BaseIntermediateOutputPath=${GUARD_LOADER_DIR}/obj/" -p:NuGetAudit=false
    COMMAND "${CMAKE_COMMAND}" -E touch "${CMAKE_CURRENT_BINARY_DIR}/embedded.rc"
    DEPENDS src/loader/GuardLoader.csproj src/loader/Entry.cs VERBATIM)
add_custom_target(GuardAst DEPENDS "${GUARD_AST_DLL}" "${GUARD_LOADER_DLL}")
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/embedded.rc" PROPERTIES OBJECT_DEPENDS "${GUARD_AST_DLL};${GUARD_LOADER_DLL}")
add_library(PowerShell7Guard SHARED src/provider/AmsiProvider.cpp src/provider/Capture.cpp src/provider/Policy.cpp src/provider/AstBridge.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/embedded.rc" src/provider/AmsiProvider.def)
add_dependencies(PowerShell7Guard GuardAst)
set(GUARD_JOURNAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/logs")
configure_file(src/provider/JournalPath.h.in JournalPath.h @ONLY)
target_include_directories(PowerShell7Guard PRIVATE "${CMAKE_CURRENT_BINARY_DIR}")
add_custom_target(GuardLogReader ALL
    COMMAND "${CARGO_EXE}" build --locked --release --manifest-path "${CMAKE_CURRENT_SOURCE_DIR}/src/reader/Cargo.toml"
        --target-dir "${CMAKE_CURRENT_BINARY_DIR}/reader"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_BINARY_DIR}/reader/release/guard-log.exe" "$<TARGET_FILE_DIR:PowerShell7Guard>/guard-log.exe"
    VERBATIM)
add_library(UpstreamAmsiProvider SHARED upstream/AmsiProvider.cpp upstream/AmsiProvider.def)
foreach(target PowerShell7Guard UpstreamAmsiProvider)
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE)
    target_link_libraries(${target} PRIVATE advapi32 ole32 runtimeobject)
endforeach()

enable_testing()
add_executable(ProviderTest tests/ProviderTest.cpp)
target_link_libraries(ProviderTest PRIVATE ole32)
add_executable(RegistrationTest tests/RegistrationTest.cpp)
target_link_libraries(RegistrationTest PRIVATE advapi32)
add_library(GuardFixture SHARED tests/ProviderTest.cpp)
target_compile_definitions(GuardFixture PRIVATE GUARD_FIXTURE_DLL)
target_link_libraries(GuardFixture PRIVATE ole32)
add_test(NAME upstream_baseline COMMAND ProviderTest $<TARGET_FILE:UpstreamAmsiProvider> baseline)
add_test(NAME guard_provider COMMAND ProviderTest $<TARGET_FILE:PowerShell7Guard> guard)
add_test(NAME runspace_data_flow COMMAND pwsh -NoProfile -File "${CMAKE_SOURCE_DIR}/tests/Test-DataFlow.ps1" -Bridge "${GUARD_AST_DLL}")
set_tests_properties(runspace_data_flow PROPERTIES TIMEOUT 30)
add_test(NAME runspace_sensitive_rules COMMAND pwsh -NoProfile -File "${CMAKE_SOURCE_DIR}/tests/Test-SensitiveRules.ps1" -WorkRoot "${CMAKE_CURRENT_BINARY_DIR}/rule-test-work")
set_tests_properties(runspace_sensitive_rules PROPERTIES TIMEOUT 90)
add_test(NAME rollback_preflight COMMAND pwsh -NoProfile -File ${CMAKE_SOURCE_DIR}/scripts/Uninstall-Guard.ps1 -CheckOnly)

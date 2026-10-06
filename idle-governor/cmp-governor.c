#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_GPUS 64U
#define NVML_SUCCESS 0
#define NVAPI_OK 0

#define CMP_50HX_PCI_ID 0x1e0910deU
#define CMP_90HX_PCI_ID 0x220d10deU

#define NVAPI_ENUM_PHYSICAL_GPUS 0xe5ac921fU
#define NVAPI_GPU_GET_BUS_ID 0x1be0b8e5U
#define NVAPI_GPU_SET_FORCE_PSTATE 0x025bfb10U
#define NVAPI_INITIALIZE 0x0150e828U
#define NVAPI_UNLOAD 0xd22bdd7eU

#define PSTATE_LOW 8U
#define PSTATE_AUTO 16U

typedef int nvmlReturn_t;
typedef void *nvmlDevice_t;
typedef int32_t NvAPI_Status;
typedef void *NvPhysicalGpuHandle;

typedef struct {
    unsigned int gpu;
    unsigned int memory;
} NvmlUtilization;

typedef struct {
    char bus_id_legacy[16];
    unsigned int domain;
    unsigned int bus;
    unsigned int device;
    unsigned int pci_device_id;
    unsigned int pci_subsystem_id;
    char bus_id[32];
} NvmlPciInfo;

typedef nvmlReturn_t (*NvmlInitFn)(void);
typedef nvmlReturn_t (*NvmlShutdownFn)(void);
typedef nvmlReturn_t (*NvmlDeviceGetCountFn)(unsigned int *);
typedef nvmlReturn_t (*NvmlDeviceGetHandleByIndexFn)(unsigned int,
                                                      nvmlDevice_t *);
typedef nvmlReturn_t (*NvmlDeviceGetNameFn)(nvmlDevice_t, char *, unsigned int);
typedef nvmlReturn_t (*NvmlDeviceGetPciInfoFn)(nvmlDevice_t, NvmlPciInfo *);
typedef nvmlReturn_t (*NvmlDeviceGetUtilizationRatesFn)(nvmlDevice_t,
                                                         NvmlUtilization *);
typedef nvmlReturn_t (*NvmlDeviceSetPersistenceModeFn)(nvmlDevice_t,
                                                        unsigned int);
typedef nvmlReturn_t (*NvmlDeviceSetPowerLimitFn)(nvmlDevice_t,
                                                   unsigned int);
typedef nvmlReturn_t (*NvmlDeviceSetLockedClocksFn)(nvmlDevice_t,
                                                     unsigned int,
                                                     unsigned int);
typedef nvmlReturn_t (*NvmlDeviceResetLockedClocksFn)(nvmlDevice_t);
typedef nvmlReturn_t (*NvmlDeviceSetCoreOffsetFn)(nvmlDevice_t, int);
typedef nvmlReturn_t (*NvmlDeviceSetMemoryOffsetFn)(nvmlDevice_t, int);
typedef const char *(*NvmlErrorStringFn)(nvmlReturn_t);

typedef struct {
    void *library;
    NvmlInitFn init;
    NvmlShutdownFn shutdown;
    NvmlDeviceGetCountFn device_get_count;
    NvmlDeviceGetHandleByIndexFn device_get_handle;
    NvmlDeviceGetNameFn device_get_name;
    NvmlDeviceGetPciInfoFn device_get_pci_info;
    NvmlDeviceGetUtilizationRatesFn device_get_utilization;
    NvmlDeviceSetPersistenceModeFn device_set_persistence;
    NvmlDeviceSetPowerLimitFn device_set_power_limit;
    NvmlDeviceSetLockedClocksFn device_set_locked_clocks;
    NvmlDeviceResetLockedClocksFn device_reset_locked_clocks;
    NvmlDeviceSetCoreOffsetFn device_set_core_offset;
    NvmlDeviceSetMemoryOffsetFn device_set_memory_offset;
    NvmlErrorStringFn error_string;
} NvmlApi;

typedef void *(*NvapiQueryInterfaceFn)(uint32_t);
typedef NvAPI_Status (*NvapiInitializeFn)(void);
typedef NvAPI_Status (*NvapiUnloadFn)(void);
typedef NvAPI_Status (*NvapiEnumPhysicalGpusFn)(NvPhysicalGpuHandle[MAX_GPUS],
                                                 uint32_t *);
typedef NvAPI_Status (*NvapiGetBusIdFn)(NvPhysicalGpuHandle, uint32_t *);
typedef NvAPI_Status (*NvapiSetForcePstateFn)(NvPhysicalGpuHandle, uint32_t,
                                               uint32_t);

typedef struct {
    void *library;
    NvapiInitializeFn initialize;
    NvapiUnloadFn unload;
    NvapiEnumPhysicalGpusFn enum_physical_gpus;
    NvapiGetBusIdFn get_bus_id;
    NvapiSetForcePstateFn set_force_pstate;
} Nvapi;

typedef struct {
    bool has_clock;
    unsigned int clock_min;
    unsigned int clock_max;
    bool has_core_offset;
    int core_offset;
    bool has_memory_offset;
    int memory_offset;
    bool has_power_limit;
    unsigned int power_w;
    unsigned int poll_seconds;
    unsigned int idle_after;
    unsigned int utilization_threshold;
} Config;

typedef enum {
    GPU_FREE = 0,
    GPU_LOW = 1
} GpuState;

typedef struct {
    unsigned int index;
    unsigned int bus;
    nvmlDevice_t nvml;
    NvPhysicalGpuHandle nvapi;
    char name[96];
    unsigned int idle_polls;
    GpuState state;
} Gpu;

static volatile sig_atomic_t running = 1;

static void stop_handler(int signal_number) {
    (void)signal_number;
    running = 0;
}

static void log_message(const char *message) {
    fprintf(stdout, "cmp-governor: %s\n", message);
    fflush(stdout);
}

static bool parse_unsigned(const char *text, unsigned int *value) {
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT_MAX) {
        return false;
    }
    *value = (unsigned int)parsed;
    return true;
}

static bool parse_signed(const char *text, int *value) {
    char *end = NULL;
    long parsed;

    if (text == NULL || *text == '\0') {
        return false;
    }
    errno = 0;
    parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < INT_MIN ||
        parsed > INT_MAX) {
        return false;
    }
    *value = (int)parsed;
    return true;
}

static bool read_unsigned_env(const char *name, unsigned int *value) {
    const char *text = getenv(name);

    if (text == NULL) {
        return true;
    }
    if (parse_unsigned(text, value)) {
        return true;
    }
    fprintf(stderr, "cmp-governor: invalid %s=%s\n", name, text);
    return false;
}

static bool read_signed_env(const char *name, int *value, bool *present) {
    const char *text = getenv(name);

    *present = text != NULL && *text != '\0';
    if (!*present) {
        return true;
    }
    if (parse_signed(text, value)) {
        return true;
    }
    fprintf(stderr, "cmp-governor: invalid %s=%s\n", name, text);
    return false;
}

static bool load_config(Config *config) {
    const char *clock = getenv("CMP_LOAD_CLOCK");
    const char *comma;
    char first[32];
    char second[32];
    unsigned int value;

    memset(config, 0, sizeof(*config));
    config->poll_seconds = 5;
    config->idle_after = 6;
    config->utilization_threshold = 5;

    if (!read_unsigned_env("CMP_POLL", &config->poll_seconds) ||
        !read_unsigned_env("CMP_IDLE_AFTER", &config->idle_after) ||
        !read_unsigned_env("CMP_UTIL", &config->utilization_threshold)) {
        return false;
    }
    if (config->poll_seconds == 0 || config->idle_after == 0 ||
        config->utilization_threshold > 100) {
        fprintf(stderr, "cmp-governor: invalid poll, idle, or utilization setting\n");
        return false;
    }

    if (clock != NULL && *clock != '\0') {
        comma = strchr(clock, ',');
        if (comma == NULL) {
            if (!parse_unsigned(clock, &value)) {
                fprintf(stderr, "cmp-governor: invalid CMP_LOAD_CLOCK=%s\n",
                        clock);
                return false;
            }
            config->clock_min = value;
            config->clock_max = value;
        } else {
            size_t first_length = (size_t)(comma - clock);
            if (first_length == 0 || first_length >= sizeof(first) ||
                strlen(comma + 1) >= sizeof(second)) {
                fprintf(stderr, "cmp-governor: invalid CMP_LOAD_CLOCK=%s\n",
                        clock);
                return false;
            }
            memcpy(first, clock, first_length);
            first[first_length] = '\0';
            strcpy(second, comma + 1);
            if (!parse_unsigned(first, &config->clock_min) ||
                !parse_unsigned(second, &config->clock_max)) {
                fprintf(stderr, "cmp-governor: invalid CMP_LOAD_CLOCK=%s\n",
                        clock);
                return false;
            }
        }
        if (config->clock_min > config->clock_max) {
            fprintf(stderr, "cmp-governor: clock minimum is above maximum\n");
            return false;
        }
        config->has_clock = true;
    }

    if (!read_signed_env("CMP_LOAD_CORE_OFFSET", &config->core_offset,
                         &config->has_core_offset) ||
        !read_signed_env("CMP_LOAD_MEM_OFFSET", &config->memory_offset,
                         &config->has_memory_offset)) {
        return false;
    }

    if (getenv("CMP_LOAD_POWER_W") != NULL) {
        if (!parse_unsigned(getenv("CMP_LOAD_POWER_W"), &config->power_w) ||
            config->power_w == 0 || config->power_w > UINT_MAX / 1000U) {
            fprintf(stderr, "cmp-governor: invalid CMP_LOAD_POWER_W=%s\n",
                    getenv("CMP_LOAD_POWER_W"));
            return false;
        }
        config->has_power_limit = true;
    }
    return true;
}

static void *load_symbol(void *library, const char *name) {
    void *symbol = dlsym(library, name);
    if (symbol == NULL) {
        fprintf(stderr, "cmp-governor: missing symbol %s\n", name);
    }
    return symbol;
}

static bool load_nvml(NvmlApi *api) {
    memset(api, 0, sizeof(*api));
    api->library = dlopen("libnvidia-ml.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (api->library == NULL) {
        api->library = dlopen("libnvidia-ml.so", RTLD_LAZY | RTLD_LOCAL);
    }
    if (api->library == NULL) {
        fprintf(stderr, "cmp-governor: cannot load libnvidia-ml.so.1: %s\n",
                dlerror());
        return false;
    }

    api->init = (NvmlInitFn)load_symbol(api->library, "nvmlInit_v2");
    if (api->init == NULL) {
        api->init = (NvmlInitFn)load_symbol(api->library, "nvmlInit");
    }
    api->shutdown = (NvmlShutdownFn)load_symbol(api->library, "nvmlShutdown");
    api->device_get_count = (NvmlDeviceGetCountFn)load_symbol(
        api->library, "nvmlDeviceGetCount_v2");
    if (api->device_get_count == NULL) {
        api->device_get_count = (NvmlDeviceGetCountFn)load_symbol(
            api->library, "nvmlDeviceGetCount");
    }
    api->device_get_handle = (NvmlDeviceGetHandleByIndexFn)load_symbol(
        api->library, "nvmlDeviceGetHandleByIndex_v2");
    api->device_get_name = (NvmlDeviceGetNameFn)load_symbol(
        api->library, "nvmlDeviceGetName");
    api->device_get_pci_info = (NvmlDeviceGetPciInfoFn)load_symbol(
        api->library, "nvmlDeviceGetPciInfo_v3");
    if (api->device_get_pci_info == NULL) {
        api->device_get_pci_info = (NvmlDeviceGetPciInfoFn)load_symbol(
            api->library, "nvmlDeviceGetPciInfo_v2");
    }
    api->device_get_utilization = (NvmlDeviceGetUtilizationRatesFn)load_symbol(
        api->library, "nvmlDeviceGetUtilizationRates");
    api->device_set_persistence = (NvmlDeviceSetPersistenceModeFn)load_symbol(
        api->library, "nvmlDeviceSetPersistenceMode");
    api->device_set_power_limit = (NvmlDeviceSetPowerLimitFn)load_symbol(
        api->library, "nvmlDeviceSetPowerManagementLimit");
    api->device_set_locked_clocks = (NvmlDeviceSetLockedClocksFn)load_symbol(
        api->library, "nvmlDeviceSetGpuLockedClocks");
    api->device_reset_locked_clocks = (NvmlDeviceResetLockedClocksFn)load_symbol(
        api->library, "nvmlDeviceResetGpuLockedClocks");
    api->device_set_core_offset = (NvmlDeviceSetCoreOffsetFn)load_symbol(
        api->library, "nvmlDeviceSetGpcClkVfOffset");
    api->device_set_memory_offset = (NvmlDeviceSetMemoryOffsetFn)load_symbol(
        api->library, "nvmlDeviceSetMemClkVfOffset");
    api->error_string = (NvmlErrorStringFn)dlsym(api->library,
                                                  "nvmlErrorString");

    return api->init != NULL && api->shutdown != NULL &&
           api->device_get_count != NULL && api->device_get_handle != NULL &&
           api->device_get_name != NULL && api->device_get_pci_info != NULL &&
           api->device_get_utilization != NULL &&
           api->device_set_persistence != NULL &&
           api->device_set_power_limit != NULL &&
           api->device_set_locked_clocks != NULL &&
           api->device_reset_locked_clocks != NULL &&
           api->device_set_core_offset != NULL &&
           api->device_set_memory_offset != NULL;
}

static bool nvml_ok(const NvmlApi *api, const char *operation,
                    nvmlReturn_t status) {
    if (status == NVML_SUCCESS) {
        return true;
    }
    fprintf(stderr, "cmp-governor: %s failed: %s (%d)\n", operation,
            api->error_string != NULL ? api->error_string(status) : "NVML error",
            status);
    return false;
}

static void unload_nvml(NvmlApi *api, bool initialized) {
    if (initialized && api->shutdown != NULL) {
        api->shutdown();
    }
    if (api->library != NULL) {
        dlclose(api->library);
    }
    memset(api, 0, sizeof(*api));
}

static bool load_nvapi(Nvapi *api) {
    NvapiQueryInterfaceFn query;

    memset(api, 0, sizeof(*api));
    api->library = dlopen("libnvidia-api.so.1", RTLD_LAZY | RTLD_LOCAL);
    if (api->library == NULL) {
        api->library = dlopen("libnvidia-api.so", RTLD_LAZY | RTLD_LOCAL);
    }
    if (api->library == NULL) {
        fprintf(stderr, "cmp-governor: cannot load libnvidia-api.so.1: %s\n",
                dlerror());
        return false;
    }
    query = (NvapiQueryInterfaceFn)load_symbol(api->library,
                                               "nvapi_QueryInterface");
    if (query == NULL) {
        return false;
    }

    api->initialize = (NvapiInitializeFn)query(NVAPI_INITIALIZE);
    api->unload = (NvapiUnloadFn)query(NVAPI_UNLOAD);
    api->enum_physical_gpus = (NvapiEnumPhysicalGpusFn)query(
        NVAPI_ENUM_PHYSICAL_GPUS);
    api->get_bus_id = (NvapiGetBusIdFn)query(NVAPI_GPU_GET_BUS_ID);
    api->set_force_pstate = (NvapiSetForcePstateFn)query(
        NVAPI_GPU_SET_FORCE_PSTATE);
    if (api->initialize == NULL || api->unload == NULL ||
        api->enum_physical_gpus == NULL || api->get_bus_id == NULL ||
        api->set_force_pstate == NULL) {
        fprintf(stderr, "cmp-governor: required NVAPI entry point is missing\n");
        return false;
    }
    if (api->initialize() != NVAPI_OK) {
        fprintf(stderr, "cmp-governor: NvAPI_Initialize failed\n");
        return false;
    }
    return true;
}

static void unload_nvapi(Nvapi *api, bool initialized) {
    if (initialized && api->unload != NULL) {
        api->unload();
    }
    if (api->library != NULL) {
        dlclose(api->library);
    }
    memset(api, 0, sizeof(*api));
}

static bool find_nvapi_gpu(const Nvapi *api, unsigned int bus,
                           NvPhysicalGpuHandle *result) {
    NvPhysicalGpuHandle handles[MAX_GPUS] = {0};
    uint32_t count = 0;
    uint32_t api_bus;

    if (api->enum_physical_gpus(handles, &count) != NVAPI_OK) {
        fprintf(stderr, "cmp-governor: NvAPI GPU enumeration failed\n");
        return false;
    }
    if (count > MAX_GPUS) {
        count = MAX_GPUS;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (api->get_bus_id(handles[i], &api_bus) == NVAPI_OK &&
            api_bus == bus) {
            *result = handles[i];
            return true;
        }
    }
    return false;
}

static bool supported_pci_id(unsigned int pci_device_id) {
    return pci_device_id == CMP_50HX_PCI_ID ||
           pci_device_id == CMP_90HX_PCI_ID;
}

static unsigned int discover_gpus(const NvmlApi *nvml, const Nvapi *nvapi,
                                  Gpu *gpus) {
    unsigned int device_count = 0;
    unsigned int managed = 0;

    if (!nvml_ok(nvml, "nvmlDeviceGetCount_v2",
                 nvml->device_get_count(&device_count))) {
        return 0;
    }
    if (device_count > MAX_GPUS) {
        device_count = MAX_GPUS;
    }
    for (unsigned int i = 0; i < device_count; ++i) {
        nvmlDevice_t device = NULL;
        NvmlPciInfo pci;
        Gpu *gpu;

        if (!nvml_ok(nvml, "nvmlDeviceGetHandleByIndex_v2",
                     nvml->device_get_handle(i, &device)) ||
            !nvml_ok(nvml, "nvmlDeviceGetPciInfo",
                     nvml->device_get_pci_info(device, &pci))) {
            continue;
        }
        if (!supported_pci_id(pci.pci_device_id)) {
            continue;
        }
        if (managed >= MAX_GPUS) {
            break;
        }
        gpu = &gpus[managed];
        memset(gpu, 0, sizeof(*gpu));
        gpu->index = i;
        gpu->bus = pci.bus;
        gpu->nvml = device;
        gpu->state = GPU_FREE;
        if (!nvml_ok(nvml, "nvmlDeviceGetName",
                     nvml->device_get_name(device, gpu->name,
                                            sizeof(gpu->name)))) {
            strcpy(gpu->name, "CMP GPU");
        }
        if (!find_nvapi_gpu(nvapi, gpu->bus, &gpu->nvapi)) {
            fprintf(stderr, "cmp-governor: %s GPU %u (PCI bus %02x) has no NVAPI handle\n",
                    gpu->name, gpu->index, gpu->bus);
            continue;
        }
        ++managed;
    }
    return managed;
}

static bool set_pstate(const Nvapi *nvapi, const Gpu *gpu,
                       unsigned int pstate) {
    NvAPI_Status status = nvapi->set_force_pstate(gpu->nvapi, pstate, 0);
    if (status == NVAPI_OK) {
        return true;
    }
    fprintf(stderr, "cmp-governor: GPU %u P%u request failed: 0x%08x\n",
            gpu->index, pstate, (uint32_t)status);
    return false;
}

static bool apply_profile(const NvmlApi *nvml, const Nvapi *nvapi,
                          const Config *config, const Gpu *gpu) {
    bool ok = true;

    if (config->has_power_limit) {
        ok = nvml_ok(nvml, "nvmlDeviceSetPowerManagementLimit",
                     nvml->device_set_power_limit(gpu->nvml,
                                                   config->power_w * 1000U)) &&
             ok;
    }
    if (config->has_memory_offset) {
        ok = nvml_ok(nvml, "nvmlDeviceSetMemClkVfOffset",
                     nvml->device_set_memory_offset(gpu->nvml,
                                                    config->memory_offset)) &&
             ok;
    }
    if (config->has_core_offset) {
        ok = nvml_ok(nvml, "nvmlDeviceSetGpcClkVfOffset",
                     nvml->device_set_core_offset(gpu->nvml,
                                                  config->core_offset)) &&
             ok;
    }
    if (config->has_clock) {
        ok = nvml_ok(nvml, "nvmlDeviceSetGpuLockedClocks",
                     nvml->device_set_locked_clocks(gpu->nvml,
                                                    config->clock_min,
                                                    config->clock_max)) &&
             ok;
    }
    if (!set_pstate(nvapi, gpu, PSTATE_AUTO)) {
        ok = false;
    }
    return ok;
}

static bool force_idle(const NvmlApi *nvml, const Nvapi *nvapi,
                       const Config *config, const Gpu *gpu) {
    bool ok = true;

    if (config->has_core_offset) {
        ok = nvml_ok(nvml, "nvmlDeviceSetGpcClkVfOffset(0)",
                     nvml->device_set_core_offset(gpu->nvml, 0)) &&
             ok;
    }
    ok = nvml_ok(nvml, "nvmlDeviceResetGpuLockedClocks",
                 nvml->device_reset_locked_clocks(gpu->nvml)) &&
         ok;
    if (!set_pstate(nvapi, gpu, PSTATE_LOW)) {
        ok = false;
    }
    return ok;
}

static bool release_gpu(const NvmlApi *nvml, const Nvapi *nvapi,
                        const Config *config, const Gpu *gpu) {
    bool ok = true;

    if (config->has_core_offset) {
        ok = nvml_ok(nvml, "nvmlDeviceSetGpcClkVfOffset(restore)",
                     nvml->device_set_core_offset(gpu->nvml,
                                                  config->core_offset)) &&
             ok;
    }
    if (config->has_clock) {
        ok = nvml_ok(nvml, "nvmlDeviceSetGpuLockedClocks(restore)",
                     nvml->device_set_locked_clocks(gpu->nvml,
                                                    config->clock_min,
                                                    config->clock_max)) &&
             ok;
    } else {
        ok = nvml_ok(nvml, "nvmlDeviceResetGpuLockedClocks",
                     nvml->device_reset_locked_clocks(gpu->nvml)) &&
             ok;
    }
    if (!set_pstate(nvapi, gpu, PSTATE_AUTO)) {
        ok = false;
    }
    return ok;
}

static void sleep_seconds(unsigned int seconds) {
    struct timespec delay = {
        .tv_sec = (time_t)seconds,
        .tv_nsec = 0
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR && running) {
    }
}

static void print_help(const char *program) {
    printf("Usage: %s [--release]\n", program);
    printf("Reads CMP_POLL, CMP_IDLE_AFTER, CMP_UTIL and CMP_LOAD_* from the environment.\n");
}

int main(int argc, char **argv) {
    NvmlApi nvml = {0};
    Nvapi nvapi = {0};
    Config config;
    Gpu gpus[MAX_GPUS];
    unsigned int gpu_count;
    bool nvml_initialized = false;
    bool nvapi_initialized = false;
    bool release_only = false;
    struct sigaction action;
    int result = 1;

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--release") != 0 &&
                     strcmp(argv[1], "--help") != 0 &&
                     strcmp(argv[1], "-h") != 0)) {
        print_help(argv[0]);
        return 2;
    }
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 ||
                      strcmp(argv[1], "-h") == 0)) {
        print_help(argv[0]);
        return 0;
    }
    release_only = argc == 2 && strcmp(argv[1], "--release") == 0;

    if (!load_config(&config) || !load_nvml(&nvml) || !load_nvapi(&nvapi)) {
        unload_nvapi(&nvapi, false);
        unload_nvml(&nvml, false);
        return 1;
    }
    if (!nvml_ok(&nvml, "nvmlInit", nvml.init())) {
        unload_nvapi(&nvapi, true);
        unload_nvml(&nvml, false);
        return 1;
    }
    nvml_initialized = true;
    nvapi_initialized = true;

    gpu_count = discover_gpus(&nvml, &nvapi, gpus);
    if (gpu_count == 0) {
        log_message("no supported CMP card found; nothing to manage");
        result = 0;
        goto cleanup;
    }
    for (unsigned int i = 0; i < gpu_count; ++i) {
        if (!nvml.device_set_persistence ||
            !nvml_ok(&nvml, "nvmlDeviceSetPersistenceMode",
                     nvml.device_set_persistence(gpus[i].nvml, 1))) {
            fprintf(stderr, "cmp-governor: GPU %u persistence mode was not set\n",
                    gpus[i].index);
        }
        if (!release_only && !apply_profile(&nvml, &nvapi, &config, &gpus[i])) {
            fprintf(stderr, "cmp-governor: GPU %u profile setup failed\n",
                    gpus[i].index);
            goto cleanup;
        }
        if (release_only && !release_gpu(&nvml, &nvapi, &config, &gpus[i])) {
            fprintf(stderr, "cmp-governor: GPU %u release failed\n", gpus[i].index);
            goto cleanup;
        }
    }
    if (release_only) {
        result = 0;
        goto cleanup;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = stop_handler;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    log_message("running as one C executable; no shell, Python, or nvidia-smi calls");
    for (unsigned int i = 0; i < gpu_count; ++i) {
        fprintf(stdout, "cmp-governor: managing GPU %u: %s (PCI bus %02x)\n",
                gpus[i].index, gpus[i].name, gpus[i].bus);
    }
    fflush(stdout);

    while (running) {
        for (unsigned int i = 0; i < gpu_count; ++i) {
            NvmlUtilization utilization;
            Gpu *gpu = &gpus[i];

            if (!nvml_ok(&nvml, "nvmlDeviceGetUtilizationRates",
                         nvml.device_get_utilization(gpu->nvml,
                                                     &utilization))) {
                goto cleanup;
            }
            if (utilization.gpu <= config.utilization_threshold) {
                if (gpu->idle_polls < UINT_MAX) {
                    ++gpu->idle_polls;
                }
                if (gpu->state == GPU_FREE &&
                    gpu->idle_polls >= config.idle_after) {
                    if (force_idle(&nvml, &nvapi, &config, gpu)) {
                        gpu->state = GPU_LOW;
                        fprintf(stdout,
                                "cmp-governor: GPU %u idle, forced P8\n",
                                gpu->index);
                        fflush(stdout);
                    } else {
                        fprintf(stderr,
                                "cmp-governor: GPU %u P8 request failed\n",
                                gpu->index);
                    }
                }
            } else {
                gpu->idle_polls = 0;
                if (gpu->state == GPU_LOW) {
                    if (release_gpu(&nvml, &nvapi, &config, gpu)) {
                        gpu->state = GPU_FREE;
                        fprintf(stdout,
                                "cmp-governor: GPU %u busy (%u%%), restored load profile\n",
                                gpu->index, utilization.gpu);
                        fflush(stdout);
                    } else {
                        fprintf(stderr,
                                "cmp-governor: GPU %u profile restore failed\n",
                                gpu->index);
                    }
                }
            }
        }
        sleep_seconds(config.poll_seconds);
    }
    result = 0;

cleanup:
    if (nvapi_initialized) {
        for (unsigned int i = 0; i < gpu_count; ++i) {
            if (!release_gpu(&nvml, &nvapi, &config, &gpus[i])) {
                result = 1;
            }
        }
    }
    unload_nvapi(&nvapi, nvapi_initialized);
    unload_nvml(&nvml, nvml_initialized);
    return result;
}

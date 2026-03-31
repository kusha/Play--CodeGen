#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <algorithm>
#include <cstdint>
#include "AlignedAlloc.h"
#include "MemoryFunction.h"

// clang-format off

#define BLOCK_ALIGN 0x10

#ifdef _WIN32
	#define MEMFUNC_USE_WIN32
#elif defined(__APPLE__)
	#include "TargetConditionals.h"
	#include <libkern/OSCacheControl.h>

	#if TARGET_OS_OSX
		#define MEMFUNC_USE_MMAP
		#define MEMFUNC_MMAP_ADDITIONAL_FLAGS (MAP_JIT)
		#if TARGET_CPU_ARM64
			#define MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
		#endif
	#elif TARGET_OS_IPHONE
		#define MEMFUNC_USE_IOS_JIT
	#else
		#define MEMFUNC_USE_MACHVM
	#endif
#elif defined(__EMSCRIPTEN__)
	#include <emscripten.h>
	#define MEMFUNC_USE_WASM
#else
	#define MEMFUNC_USE_MMAP
#endif

#if defined(MEMFUNC_USE_WIN32)
#include <windows.h>
#elif defined(MEMFUNC_USE_MACHVM)
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#elif defined(MEMFUNC_USE_IOS_JIT)
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <os/log.h>
#elif defined(MEMFUNC_USE_MMAP)
#include <sys/mman.h>
#include <pthread.h>
#elif defined(MEMFUNC_USE_WASM)
EM_JS_DEPS(WasmMemoryFunction, "$addFunction,$removeFunction");
EM_JS(int, WasmCreateFunction, (emscripten::EM_VAL moduleHandle),
{
	let module = Emval.toValue(moduleHandle);
	let moduleInstance = new WebAssembly.Instance(module, {
		env: {
			memory: wasmMemory,
			fctTable : Module.codeGenImportTable
		}
	});
	let fct = moduleInstance.exports.codeGenFunc;
	let fctId = addFunction(fct, 'vi');
	return fctId;
});
EM_JS(void, WasmDeleteFunction, (int fctId),
{
	removeFunction(fctId);
});
EM_JS(emscripten::EM_VAL, WasmCreateModule, (uintptr_t code, uintptr_t size),
{
	//var fs = require('fs');
	let moduleBytes = HEAP8.subarray(code, code + size);
	//fs.writeFileSync('module.wasm', moduleBytes);
	//{
	//	let bytesCopy = new Uint8Array(moduleBytes);
	//	let blob = new Blob([bytesCopy], { type: "binary/octet-stream" });
	//	let url = URL.createObjectURL(blob);
	//	console.log(url);
	//}
	let module = new WebAssembly.Module(moduleBytes);
	return Emval.toHandle(module);
});
#else
#error "No API to use for CMemoryFunction"
#endif

#ifdef MEMFUNC_USE_IOS_JIT
#include <errno.h>

extern "C" int csops(pid_t pid, unsigned int ops, void* useraddr, size_t usersize);

static os_log_t GetJitLog()
{
	static os_log_t log = os_log_create("org.puredarwin.play", "jit");
	return log;
}

static bool IsProcessDebugged()
{
	uint32_t flags = 0;
	if(csops(getpid(), 0 /* CS_OPS_STATUS */, &flags, sizeof(flags)) != 0) return false;
	return (flags & 0x10000000 /* CS_DEBUGGED */) != 0;
}

static bool WaitForDebugger(int maxWaitMs = 10000)
{
	if(IsProcessDebugged()) return true;
	for(int waited = 0; waited < maxWaitMs; waited += 50)
	{
		usleep(50000);
		if(IsProcessDebugged()) return true;
	}
	return false;
}

enum class IosJitStrategy
{
	None,
	MapJit,
	RxMprotect,
};

static IosJitStrategy g_jitStrategy = IosJitStrategy::None;

typedef void (*PthreadJitWriteProtectFn)(int);
static PthreadJitWriteProtectFn g_pthreadJitWriteProtect = nullptr;

static bool InitJitWriteProtect()
{
	if(g_pthreadJitWriteProtect) return true;
	g_pthreadJitWriteProtect = (PthreadJitWriteProtectFn)dlsym(RTLD_DEFAULT, "pthread_jit_write_protect_np");
	return g_pthreadJitWriteProtect != nullptr;
}

static void JitWriteProtect(bool protect)
{
	if(g_pthreadJitWriteProtect)
		g_pthreadJitWriteProtect(protect ? 1 : 0);
}

static void* AllocateMapJit(size_t allocSize)
{
	if(!InitJitWriteProtect())
	{
		os_log_error(GetJitLog(), "pthread_jit_write_protect_np not available");
		return nullptr;
	}

	void* p = mmap(nullptr, allocSize, PROT_READ | PROT_WRITE | PROT_EXEC,
	               MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
	if(p == MAP_FAILED)
	{
		os_log_error(GetJitLog(), "MAP_JIT failed: errno=%d (%{public}s)", errno, strerror(errno));
		return nullptr;
	}
	os_log_info(GetJitLog(), "MAP_JIT succeeded at %p size=%zu", p, allocSize);
	return p;
}

static void* AllocateRxMprotect(size_t allocSize)
{
	void* p = mmap(nullptr, allocSize, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
	if(p == MAP_FAILED)
	{
		os_log_error(GetJitLog(), "RX mmap failed: errno=%d (%{public}s)", errno, strerror(errno));
		return nullptr;
	}
	if(mprotect(p, allocSize, PROT_READ | PROT_WRITE) != 0)
	{
		os_log_error(GetJitLog(), "RX->RW toggle failed: errno=%d (%{public}s)", errno, strerror(errno));
		munmap(p, allocSize);
		return nullptr;
	}
	if(mprotect(p, allocSize, PROT_READ | PROT_EXEC) != 0)
	{
		os_log_error(GetJitLog(), "RW->RX toggle failed: errno=%d (%{public}s)", errno, strerror(errno));
		munmap(p, allocSize);
		return nullptr;
	}
	os_log_info(GetJitLog(), "RX mprotect strategy succeeded at %p size=%zu", p, allocSize);
	return p;
}
#endif

CMemoryFunction::CMemoryFunction()
: m_code(nullptr)
, m_codeRW(nullptr)
, m_size(0)
{

}

CMemoryFunction::CMemoryFunction(CMemoryFunction&& rhs)
: m_code(nullptr)
, m_codeRW(nullptr)
, m_size(0)
{
	std::swap(m_code, rhs.m_code);
	std::swap(m_codeRW, rhs.m_codeRW);
	std::swap(m_size, rhs.m_size);
#if defined(MEMFUNC_USE_WASM)
	std::swap(m_wasmModule, rhs.m_wasmModule);
#endif
}

CMemoryFunction::CMemoryFunction(const void* code, size_t size)
: m_code(nullptr)
, m_codeRW(nullptr)
{
#if defined(MEMFUNC_USE_WIN32)
	m_size = size;
	m_code = framework_aligned_alloc(size, BLOCK_ALIGN);
	memcpy(m_code, code, size);
	
	DWORD oldProtect = 0;
	BOOL result = VirtualProtect(m_code, size, PAGE_EXECUTE_READWRITE, &oldProtect);
	assert(result == TRUE);
#elif defined(MEMFUNC_USE_MACHVM)
	vm_size_t page_size = 0;
	host_page_size(mach_task_self(), &page_size);
	unsigned int allocSize = ((size + page_size - 1) / page_size) * page_size;
	vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&m_code), allocSize, TRUE); 
	memcpy(m_code, code, size);
	vm_prot_t protection =
	#ifdef MEMFUNC_MACHVM_STRICT_PROTECTION
		VM_PROT_READ | VM_PROT_EXECUTE;
	#else
		VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
	#endif
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), size, 0, protection);
	assert(result == 0);
	m_size = allocSize;
#elif defined(MEMFUNC_USE_IOS_JIT)
	long page_size = sysconf(_SC_PAGESIZE);
	size_t allocSize = ((size + page_size - 1) / page_size) * page_size;

	WaitForDebugger();

	void* jitMem = AllocateMapJit(allocSize);
	if(jitMem)
	{
		g_jitStrategy = IosJitStrategy::MapJit;
		m_code = jitMem;
		m_codeRW = jitMem;
		JitWriteProtect(false);
		memcpy(m_code, code, size);
		JitWriteProtect(true);
		m_size = allocSize;
	}
	else
	{
		void* rxMem = AllocateRxMprotect(allocSize);
		if(rxMem)
		{
			g_jitStrategy = IosJitStrategy::RxMprotect;
			m_code = rxMem;
			m_codeRW = rxMem;
			mprotect(m_code, allocSize, PROT_READ | PROT_WRITE);
			memcpy(m_code, code, size);
			mprotect(m_code, allocSize, PROT_READ | PROT_EXEC);
			m_size = allocSize;
		}
		else
		{
			os_log_fault(GetJitLog(), "All JIT strategies failed — aborting");
			abort();
		}
	}
#elif defined(MEMFUNC_USE_MMAP)
	uint32 additionalMapFlags = 0;
	#ifdef MEMFUNC_MMAP_ADDITIONAL_FLAGS
		additionalMapFlags = MEMFUNC_MMAP_ADDITIONAL_FLAGS;
	#endif
	m_size = size;
	m_code = mmap(nullptr, size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | additionalMapFlags, -1, 0);
	assert(m_code != MAP_FAILED);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(false);
#endif
	memcpy(m_code, code, size);
#ifdef MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT
	pthread_jit_write_protect_np(true);
#endif
#elif defined(MEMFUNC_USE_WASM)
	m_wasmModule = emscripten::val::take_ownership(WasmCreateModule(reinterpret_cast<uintptr_t>(code), size));
	m_size = size;
	m_code = reinterpret_cast<void*>(WasmCreateFunction(m_wasmModule.as_handle()));
#endif
	ClearCache();
#if !defined(MEMFUNC_USE_WASM)
	assert((reinterpret_cast<uintptr_t>(m_code) & (BLOCK_ALIGN - 1)) == 0);
#endif
}

CMemoryFunction::~CMemoryFunction()
{
	Reset();
}

void CMemoryFunction::ClearCache()
{
#ifdef __APPLE__
	sys_icache_invalidate(m_code, m_size);
#elif defined(MEMFUNC_USE_MMAP)
	#if defined(__arm__) || defined(__aarch64__)
		__clear_cache(m_code, reinterpret_cast<uint8*>(m_code) + m_size);
	#endif
#endif
}

void CMemoryFunction::Reset()
{
	if(m_code != nullptr)
	{
#if defined(MEMFUNC_USE_WIN32)
		framework_aligned_free(m_code);
#elif defined(MEMFUNC_USE_MACHVM)
		vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size);
#elif defined(MEMFUNC_USE_IOS_JIT)
		munmap(m_code, m_size);
#elif defined(MEMFUNC_USE_MMAP)
		munmap(m_code, m_size);
#elif defined(MEMFUNC_USE_WASM)
		WasmDeleteFunction(reinterpret_cast<int>(m_code));
#endif
	}
	m_code = nullptr;
	m_codeRW = nullptr;
	m_size = 0;
#if defined(MEMFUNC_USE_WASM)
	m_wasmModule = emscripten::val();
#endif
}

bool CMemoryFunction::IsEmpty() const
{
	return m_code == nullptr;
}

CMemoryFunction& CMemoryFunction::operator =(CMemoryFunction&& rhs)
{
	Reset();
	std::swap(m_code, rhs.m_code);
	std::swap(m_codeRW, rhs.m_codeRW);
	std::swap(m_size, rhs.m_size);
#if defined(MEMFUNC_USE_WASM)
	std::swap(m_wasmModule, rhs.m_wasmModule);
#endif
	return (*this);
}

void CMemoryFunction::operator()(void* context)
{
	typedef void (*FctType)(void*);
	auto fct = reinterpret_cast<FctType>(m_code);
	fct(context);
}

void* CMemoryFunction::GetCode() const
{
	return m_code;
}

size_t CMemoryFunction::GetSize() const
{
	return m_size;
}

void CMemoryFunction::BeginModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size, 0, VM_PROT_READ | VM_PROT_WRITE);
	assert(result == 0);
#elif defined(MEMFUNC_USE_IOS_JIT)
	switch(g_jitStrategy)
	{
	case IosJitStrategy::MapJit:
		JitWriteProtect(false);
		break;
	case IosJitStrategy::RxMprotect:
		mprotect(m_code, m_size, PROT_READ | PROT_WRITE);
		break;
	default:
		break;
	}
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(false);
#endif
}

void CMemoryFunction::EndModify()
{
#if defined(MEMFUNC_USE_MACHVM) && defined(MEMFUNC_MACHVM_STRICT_PROTECTION)
	kern_return_t result = vm_protect(mach_task_self(), reinterpret_cast<vm_address_t>(m_code), m_size, 0, VM_PROT_READ | VM_PROT_EXECUTE);
	assert(result == 0);
#elif defined(MEMFUNC_USE_IOS_JIT)
	switch(g_jitStrategy)
	{
	case IosJitStrategy::MapJit:
		JitWriteProtect(true);
		break;
	case IosJitStrategy::RxMprotect:
		mprotect(m_code, m_size, PROT_READ | PROT_EXEC);
		break;
	default:
		break;
	}
#elif defined(MEMFUNC_USE_MMAP) && defined(MEMFUNC_MMAP_REQUIRES_JIT_WRITE_PROTECT)
	pthread_jit_write_protect_np(true);
#endif
	ClearCache();
}

CMemoryFunction CMemoryFunction::CreateInstance()
{
#if defined(MEMFUNC_USE_WASM)
	CMemoryFunction result;
	result.m_wasmModule = m_wasmModule;
	result.m_size = m_size;
	result.m_code = reinterpret_cast<void*>(WasmCreateFunction(m_wasmModule.as_handle()));
	return result;
#else
	return CMemoryFunction(GetCode(), GetSize());
#endif
}

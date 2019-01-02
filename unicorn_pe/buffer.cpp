#include <Windows.h>
#include <memory>
#include "buffer.h"

virtual_buffer_t::virtual_buffer_t() : m_cbSize(0), m_pBuffer(NULL)
{
}
virtual_buffer_t::virtual_buffer_t(size_t size) : m_cbSize(size), m_pBuffer(VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE))
{
}

virtual_buffer_t::~virtual_buffer_t()
{
	if (m_pBuffer)
		VirtualFree(m_pBuffer, 0, MEM_RELEASE);
}

void * virtual_buffer_t::GetSpace(size_t needSize)
{
	if (m_cbSize < needSize)
	{
		if (m_pBuffer)
			VirtualFree(m_pBuffer, 0, MEM_RELEASE);
		m_pBuffer = VirtualAlloc(NULL, needSize, MEM_COMMIT, PAGE_READWRITE);
		m_cbSize = needSize;
	}
	return m_pBuffer;
}

crt_buffer_t::crt_buffer_t() : m_cbSize(0), m_pBuffer(NULL)
{
}

crt_buffer_t::crt_buffer_t(size_t size) : m_cbSize(size), m_pBuffer(malloc(size))
{
}

crt_buffer_t::~crt_buffer_t()
{
	if (m_pBuffer)
		free(m_pBuffer);
}

void * crt_buffer_t::GetSpace(size_t needSize)
{
	if (m_cbSize < needSize)
	{
		if (m_pBuffer)
			m_pBuffer = realloc(m_pBuffer, needSize);
		else
			m_pBuffer = malloc(needSize);
		m_cbSize = needSize;
	}
	return m_pBuffer;
}
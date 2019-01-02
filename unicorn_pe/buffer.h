#pragma once

class virtual_buffer_t
{
public:
	virtual_buffer_t();
	virtual_buffer_t(size_t size);
	~virtual_buffer_t();
	void * GetSpace(size_t needSize);
	size_t GetLength() { return m_cbSize; }
	void * GetBuffer() { return m_pBuffer; }

	void * m_pBuffer;
	size_t m_cbSize;
};

class crt_buffer_t
{
public:
	crt_buffer_t();
	crt_buffer_t(size_t size);
	~crt_buffer_t();
	void * GetSpace(size_t needSize);
	size_t GetLength() { return m_cbSize; }
	void * GetBuffer() { return m_pBuffer; }

	void * m_pBuffer;
	size_t m_cbSize;
};
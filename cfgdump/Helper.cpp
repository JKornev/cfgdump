#include "Helper.h"
#include <stdarg.h>
#include <Windows.h>
#include <wdbgexts.h>

using namespace std;

// =================

Exception::Exception(const char* Format, ...)
{
	char buffer[256];

	va_list args;
	va_start(args, Format);
	_vsnprintf_s(buffer, _countof(buffer), _TRUNCATE, Format, args);
	va_end(args);

	m_errorMessage = buffer;
}

const char* Exception::What()
{
	return m_errorMessage.c_str();
}

// =================


Arguments::Arguments(const char* commandLine) : m_argPointer(0)
{
	if (!commandLine)
		return;

	char* context;
	auto tokens = _strdup(commandLine);
	auto token = strtok_s(tokens, " ", &context);
	
	if (!token)
		return;

	do { 
		m_arguments.push_back(token);
	} while (token = strtok_s(nullptr, " ", &context));

	free(tokens);
}

size_t Arguments::ArgsCount()
{
	return m_arguments.size();
}

bool Arguments::Probe(std::string& arg)
{
	if (m_argPointer >= m_arguments.size())
		return false;

	arg = m_arguments[m_argPointer];
	return true;
}

bool Arguments::SwitchToNext()
{
	if (m_argPointer >= m_arguments.size())
		return false;

	m_argPointer++;
	return true;
}

bool Arguments::GetNext(string& arg)
{
	if (m_argPointer >= m_arguments.size())
		return false;

	arg = m_arguments[m_argPointer++];
	return true;
}

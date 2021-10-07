#pragma once

#include <vector>
#include <string>

class Exception
{
	std::string m_errorMessage;

public:

	Exception(const char* Format, ...);

	const char* What();
};

class Arguments
{
	std::vector<std::string> m_arguments;
	unsigned int m_argPointer;

public:

	Arguments(const char* commandLine);

	size_t ArgsCount();

	bool Probe(std::string& arg);
	bool SwitchToNext();
	bool GetNext(std::string& arg);
};

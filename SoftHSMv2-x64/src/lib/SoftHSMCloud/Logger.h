#pragma once

#include <memory>
#include <string>
#include <iostream>
#include <fstream>


class Logger
{
public:
	static Logger* i();

	virtual ~Logger() {
		file.close();
	};

	void logDebug(std::string function, int line, std::string message, std::string additional = "");

private:
	Logger() {
		filePath = "debug.txt";
		file = std::ofstream(filePath);
	};

	// The one-and-only instance
#ifdef HAVE_CXX11
	static std::unique_ptr<Logger> instance;
#else
	static std::auto_ptr<Logger> instance;
#endif

	std::string filePath;
	std::ofstream file;
};

#ifdef HAVE_CXX11
std::unique_ptr<Logger> Logger::instance(nullptr);
#else
std::auto_ptr<Logger> Logger::instance(NULL);
#endif

inline Logger* Logger::i()
{
	if (!instance.get())
	{
		instance.reset(new Logger());
	}

	return instance.get();
}

inline void Logger::logDebug(std::string function, int line, std::string message, std::string additional)
{
	file << "[" << function << " - " << line << "]" << message << "[" << additional << "]";
}

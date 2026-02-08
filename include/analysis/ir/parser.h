/*
    Copyright (C) 2018 - 2026 Huan Nguyen.
 */

#ifndef PARSER_H
#define PARSER_H

#include <string>

namespace SBA {
   /* Forward declaration */
   class RTL;
   /* ------------------------------- Parser -------------------------------- */
   class Parser {
    public:
      Parser() {};
      static RTL* process(const std::string& _s);
   };
}

#endif

#include <iostream>
#include <fstream>
#include <optional>
#include <unordered_set>
#include <sstream>
#include <stdint.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAXLINELENGTH 1000


namespace authenticator {
    std::unordered_set<std::string> labels;
    std::unordered_set<std::string> opcodes;
    static inline std::size_t curr_pc; 
    struct line {
    [[maybe_unused]]    std::optional<std::string> m_label;
                        std::string m_Opcode;
                        ssize_t m_RegA;
                        ssize_t m_RegB;
    [[maybe_unused]]    std::optional<ssize_t> m_RegDest;
    [[maybe_unused]]    std::optional<ssize_t> offset;
    [[maybe_unused]]    std::optional<std::string> m_label_dest;
    line(std::string m_label_in, std::string m_opcode_in, ssize_t m_regA_in, ssize_t, ssize_t m_RegB_in, ssize_t m_RegDest_in, ssize_t offset_in, std::string m_label_dest_in) :
        m_label(m_label_in), m_Opcode(m_opcode_in), m_RegA(m_regA_in), m_RegB(m_RegB_in), m_RegDest(m_RegDest_in), offset(offset_in), m_label_dest(m_label_dest_in) {}
    };


  [[nodiscard]] static inline std::optional<line> readAndParse(FILE* inFilePtr) noexcept{
	char Fileline[MAXLINELENGTH];
    char label[MAXLINELENGTH], opcode[MAXLINELENGTH], arg0[MAXLINELENGTH], arg1[MAXLINELENGTH], arg2[MAXLINELENGTH];
	label[0] = opcode[0] = arg0[0] = arg1[0] = arg2[0] = '\0';
	if (fgets(Fileline, MAXLINELENGTH, inFilePtr) == NULL) {
		return {};
	}
	if (strchr(Fileline, '\n') == NULL) {
		printf("error: line too long\n");
		return {};
	}
	char* ptr = Fileline;
	if (sscanf(ptr, "%[^\t\n\r ]", label)) {
		ptr += strlen(label);
	}
	sscanf(ptr, "%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]",
		opcode, arg0, arg1, arg2);
	std::optional<authenticator::line> victim;
    victim.value() = line((std::string)label, (std::string)opcode, (ssize_t)arg0, (ssize_t)arg1, (ssize_t)arg2, (ssize_t)arg2, (ssize_t)arg2 ,(std::string)arg2);
    return victim; 
}

    [[nodiscard]] inline std::optional<ssize_t> parse_reg(line & line_in){
            if (line_in.m_RegA < 0 || line_in.m_RegA > 8) [[unlikely]] 
                return line_in.m_RegA;
            if  (line_in.m_RegB < 0 || line_in.m_RegB > 8) [[unlikely]] 
                return line_in.m_RegB;
            if (line_in.m_RegDest.has_value()){
                if  (line_in.m_RegDest < 0 || line_in.m_RegDest >= 8) [[unlikely]] 
                    return line_in.m_RegDest;
            }
            return {}; 
    }

    [[nodiscard]] inline std::optional<std::string> parse_opcode(line & line_in) noexcept{
        auto val = [=](line victim_line) mutable-> std::string {
            std::string ret = "";
            for (uint32_t i = 0; i < line_in.m_Opcode.size(); ++i){
                ret.push_back(std::toupper(victim_line.m_Opcode[i]));
            }
            return ret; 
        }(line_in);
        if (val == "ADD" || val == "NOR" || val == "LW" || val == "SW" || val == "BEQ" || val == "JALR" || val == "NOOP" || val == "HALT") {
            return {};
        } 
        return line_in.m_Opcode;
    }

    [[nodiscard]] inline std::optional<std::string> parse_label(line & line_in) noexcept{
        if(line_in.m_label.has_value()){
            auto [first] = labels.find(line_in.m_label.value());
            if(!first) [[unlikely]] {
                return {}; 
            }
            labels.insert(line_in.m_label.value());
        }
        return std::optional<std::reference_wrapper<std::string>>{line_in.m_label.value()};
    }
}



int main(int argc, char ** argv){
    authenticator::curr_pc = 0;
    printf("Authenticating file: %s", argv[1]);
    FILE* inFileString = fopen(argv[1], "r");
    auto it = [&](std::size_t pc) mutable -> bool {
        //Run authenticator until we reach an error or EOF
         while(true){
             if(std::optional<authenticator::line> line_val = authenticator::readAndParse(inFileString); line_val){
                 if(auto reg_valid = authenticator::parse_reg(line_val.value()); reg_valid){
                    printf("Error parsing register %d on line %d",reg_valid , pc);
                     return false;
                 }
                 if (auto op = authenticator::parse_opcode(line_val.value()); op){
                     printf("Error parsing opcode %s on line %d", op, pc);
                     return false;
                 }
                if (auto label = authenticator::parse_label(line_val.value()); label){
                    printf("Error parsing label %s on line %d", label, pc);
                     return false;
                }
                authenticator::curr_pc++;
             }
         }
         return true; 
    }(authenticator::curr_pc);
    std::string output = (it) ? "Test " + (std::string)argv[1] + " authenticated." : "Test " + (std::string)argv[1] + " failed authentication.";
    std::cout << output << "\n";
    return 1; 
   
}

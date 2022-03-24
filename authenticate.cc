#pragma once

#include <iostream>
#include <optional>
#include <unordered_set>
#include <varient>
#include <vector>
#include <string>
#include <functional>
#include <algorithm>

#define MAXLINELENGTH 65000;



namespace authenticator {
    std::unordered_set<std::string> labels;
    std::unordered_set<std::string> opcodes;
    static inline std::size_t curr_pc; 
    struct line {
    [[maybe_unused]]    std::optional<std::string> m_label;
                        std::string m_Opcode;
                        std::ssize_t m_RegA;
                        std::ssize_t m_RegB;
    [[maybe_unused]]    std::optional<std::ssize_t> m_RegDest
    [[maybe_unused]]    std::optional<std::ssize_t offset
    };

    [[no_discard]] static inline std::optional<line> parse_line(){

    }

    [[no_discard]] inline std::optional<std::ssize_t> parse_reg(line & line_in){
            if (line_in.m_RegA < 0 || line_in.m_RegA > 8) [[unlikely]] 
                return line_in.m_RegA;
            if  (line_in.m_RegB < 0 || line_in.m_RegB > 8) [[unlikely]] 
                return line_in.m_RegB;
            if (line_in.m_RegDest.has_value()){
                if  (line_in.m_RegDest < 0 || line_in.m_RegDest > 8) [[unlikely]] 
                    return line_in.m_RegDest
            }
            return {}; 
    }

    [[no_discard]] inline std::optional<std::string> parse_opcode(line & line_in){
        auto val = std::to_upper(line_in.m_Opcode);
        if (val == "ADD" || val == "NOR" || val == "LW" || val == "SW" || val == "BEQ" || val == "JALR" || val == "NOOP" || val == "HALT") {
            return {};
        } 
        return line_in.m_Opcode;
    }

    [[no_discard]] inline std::optional<std::string> parse_label(line & line_in) noexcept {
        if(line_in.m_label.has_value()){
            [first, second] = labels.find(line_in.m_label);
            if(first) [[unlikely]] {
                return second; 
            }
            labels.insert(line_in.m_label);
        }
        return {};
    }
}



int main(int argc, char ** argv){
    authenticator::curr_pc = 0;
    printf("Authenticating file: %s", argv[1]);
    auto it = [&]() -> bool {
        //Run authenticator until we reach an error or EOF
         while(true){
             if(auto line_val = authenticator::parse_line(); line_val){
                 if(auto reg_valid = authenticator::parse_reg(line_val); reg_valid){
                    printf("Error parsing register %d on line %d",reg_valid , curr_pc);
                     return false;
                 }
                 if (auto op = authenticator::parse_opcode(line_val); op){
                     printf("Error parsing opcode %s on line %d", op, curr_pc);
                     return false;
                 }
                if (auto label = authenticator::parse_label(line_val); label){
                    printf("Error parsing label %s on line %d", op, curr_pc);
                     return false;
                }
                authenticator::curr_pc++;
             }
         }
    }
    std::cout << (it) ? "Test " << argv[1] << " authenticated." : "Test " << argv[1] << " failed authentication.";
    return 1; 
   
}
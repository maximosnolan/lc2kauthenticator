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
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAXLINELENGTH 1000
#define NOERR "NOERROR"
#define debug
#define LOG(indicator, msg) std::cout << indicator << ": " << msg << "\n";

enum class type {RTYPE, ITYPE, JTYPE, OTYPE};



namespace authenticator {
    std::unordered_set<std::string> labels;
    std::unordered_set<std::string> opcodes;
    static inline std::size_t curr_pc; 
    struct line {
    [[maybe_unused]]    std::optional<std::string> m_label;
                        std::string m_Opcode;
                        int32_t m_RegA;
                        int32_t m_RegB;
    [[maybe_unused]]    std::optional<ssize_t> m_RegDest;
    [[maybe_unused]]    std::optional<ssize_t> offset;
    [[maybe_unused]]    std::optional<std::string> m_label_dest;
    line(std::optional<std::string> m_label_in, std::string m_opcode_in, ssize_t m_regA_in, ssize_t, ssize_t m_RegB_in, ssize_t m_RegDest_in, ssize_t offset_in, std::optional<std::string> m_label_dest_in) :
        m_label(m_label_in), m_Opcode(m_opcode_in), m_RegA(m_regA_in), m_RegB(m_RegB_in), m_RegDest(m_RegDest_in), offset(offset_in), m_label_dest(m_label_dest_in) {}
    };

[[nodiscard, maybe_unused]] static inline type validateOp(std::string opcode_in) noexcept {
    for (auto & c: opcode_in) c = toupper(c);
    if (opcode_in == "ADD" || opcode_in == "NOR") return type::RTYPE;
    if (opcode_in == "JALR") return type::JTYPE;
    if (opcode_in == "HALT" || opcode_in == "NOOP") return type::OTYPE;
    return type::ITYPE;
}

[[nodiscard]] static inline std::optional<line> readAndParse(FILE* inFilePtr, bool supress_process) noexcept{
	char Fileline[MAXLINELENGTH];
    char label[MAXLINELENGTH], opcode[MAXLINELENGTH], arg0[MAXLINELENGTH], arg1[MAXLINELENGTH], arg2[MAXLINELENGTH];
	label[0] = opcode[0] = arg0[0] = arg1[0] = arg2[0] = '\0';
	if (fgets(Fileline, MAXLINELENGTH, inFilePtr) == NULL) {
        printf("EOF reached with zero errors. Performing post authentication\n");
		return {};
	}
	char* ptr = Fileline;
	if (sscanf(ptr, "%[^\t\n\r ]", label)) {
		ptr += strlen(label);
	}
	sscanf(ptr, "%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]%*[\t\n\r ]%[^\t\n\r ]",
		opcode, arg0, arg1, arg2);
    std::cout << "\n";
    if (!supress_process) {
       #ifdef debug
        LOG("label", label);
        LOG("opcode", opcode);
        LOG("regA", arg0);
        LOG("regB", arg1);
        LOG("destreg/offset/label", arg2);
        #endif   
    }
    std::string a = arg2; 
    std::string lab = label;
    std::string op = opcode; 
    ssize_t b = std::atoi(arg2);
    std::optional<std::string> label_usg = (strcmp(label, "") == 0) ? std::nullopt : std::optional<std::reference_wrapper<const std::string>>{lab};
    std::optional<std::string> dest_lab = (!isdigit(arg2[0]) && validateOp(op) == type::ITYPE) ? std::optional<std::reference_wrapper<const std::string>>{a} : std::nullopt ;
    std::optional<ssize_t> dest_reg = (isdigit(arg2[0]) && validateOp(op) == type::RTYPE) ? std::nullopt :  std::optional<std::reference_wrapper<ssize_t>>{b};
    std::optional<ssize_t> offset = (isdigit(arg2[0]) && validateOp(op) == type::ITYPE) ? std::nullopt : std::optional<std::reference_wrapper<ssize_t>>{b};
    line victim = line(label_usg, (std::string)opcode, (ssize_t)std::atoi(arg0), (ssize_t)std::atoi(arg1), (ssize_t)std::atoi(arg2), (ssize_t)std::atoi(arg2), (ssize_t)std::atoi(arg2) ,dest_lab);
    return std::optional<std::reference_wrapper<authenticator::line>>{victim}; 
}

    [[nodiscard]] inline std::optional<ssize_t> parse_reg(line & line_in){
        #ifdef debug
        LOG("regA value", line_in.m_RegA);
        LOG("regB value", line_in.m_RegB);
        LOG("regDest value", line_in.m_RegDest.value());
        #endif
            if (line_in.m_RegA < 0 || line_in.m_RegA > 8) [[unlikely]] 
                return line_in.m_RegA;
            if  (line_in.m_RegB < 0 || line_in.m_RegB > 8) [[unlikely]] 
                return line_in.m_RegA;
            if (line_in.m_RegDest.has_value()){
                if  (line_in.m_RegDest < 0 || line_in.m_RegDest >= 8) [[unlikely]] 
                    return line_in.m_RegA;
            }
            return {};
    }

    [[nodiscard]] inline const std::optional<std::string> parse_opcode(line & line_in) noexcept{
        auto val = [=](line victim_line) mutable-> std::string {
            std::string ret = "";
            for (uint32_t i = 0; i < line_in.m_Opcode.size(); ++i){
                ret.push_back(std::toupper(victim_line.m_Opcode[i]));
            }
            return ret; 
        }(line_in);
        if (val == "ADD" || val == "NOR" || val == "LW" || val == "SW" || val == "BEQ" || val == "JALR" || val == "NOOP" || val == "HALT") {
            return line_in.m_Opcode;
        } 
        return {};
    }

    [[nodiscard]] inline std::optional<std::string> parse_label(line & line_in) noexcept{
        if(line_in.m_label_dest){
            #ifdef debug
            LOG("has value for dest label", *line_in.m_label_dest);
            LOG("size of label map", labels.size());
            #endif
            if(auto first = labels.find(*line_in.m_label_dest); first == labels.end() && validateOp(line_in.m_Opcode) == type::ITYPE)[[unlikely]]   { 
                LOG("here", "yo");
                return {}; 
            }
        }
        return std::optional<std::reference_wrapper<std::string>>{line_in.m_Opcode};
    }

     [[nodiscard]] std::optional<uint32_t> label_map(const char * fname) noexcept {
        FILE* inFileString = fopen(fname, "r");
        uint64_t localPC = 0;
        while (true) {
              if(std::optional<authenticator::line> line_val = authenticator::readAndParse(inFileString, true); line_val){ 
                 auto& res = *line_val;
                 if(res.m_label) [[unlikely]] {
                     LOG("Label found", *res.m_label);
                     auto failure = [&](authenticator::line line_val) mutable -> std::optional<std::string>  {
                         if(auto it = labels.find(*res.m_label); it != labels.end()) {
                         #ifdef debug
                            LOG("Duplicate label found", *it);
                         #endif
                             return std::optional<std::reference_wrapper<const std::string>>{*it}; 
                         }
                         return {};
                     }(res); 
                     if (failure) {
                         LOG("returning early", "yo");
                         return std::optional<std::reference_wrapper<uint32_t>>{*reinterpret_cast<uint32_t *>(&localPC)}; 
                     }
                     labels.insert(*res.m_label);
                     localPC++;
                 }
              }
              else {
                  return {};
              }
        } 
    }



}




int main(int argc, char ** argv){
    printf("Authenticating file: %s", argv[1]);
    if (auto it = authenticator::label_map(argv[1]); !it)
        printf("Duplicate labels detected. Authentication failed for file: %s\n", argv[1]);
    FILE* inFileString = fopen(argv[1], "r");
    printf("parsing file %s for correct register usage and opcode usage... \n", argv[1]);
    auto it = [&]() mutable -> bool {
        int pc = 0;
        //Run authenticator until we reach an error or EOF
         while(true){
             printf("pc %d\n", pc);
             if(std::optional<authenticator::line> line_val = authenticator::readAndParse(inFileString, false); line_val){
                 if(auto reg_valid = authenticator::parse_reg(*line_val); reg_valid) [[unlikely]]{
                     std::cout << "Error parsing register " << *reg_valid << " on line " << pc << "\n"; 
                     return false;
                 } 
                 if (auto op = authenticator::parse_opcode(*line_val); !op) [[unlikely]]{
                     printf("Error parsing opcode %s on line %d\n", op, pc);
                     return false;
                 }
                if (auto label = authenticator::parse_label(*line_val); !label) [[unlikely]] {
                    printf("Error parsing label %s on line %d\n", label, pc);
                     return false;
                }
                pc++;
             } 
             else {
                 return true;
             }
            
         }
         return true; 
    }();
    std::string output = (it) ? "Test " + (std::string)argv[1] + " authenticated." : "Test " + (std::string)argv[1] + " failed authentication.";
    std::cout << output << "\n";
    return 1; 
   
}
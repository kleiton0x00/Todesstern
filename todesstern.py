import random
import string
from urllib.parse import quote
import configparser

class Fuzzer:
    def __init__(self, initial_seed, mutation_rate=0.2, max_mutations=10):
        self.initial_seed = initial_seed
        self.mutation_rate = mutation_rate
        self.max_mutations = max_mutations

    @staticmethod
    def _arithmetic_mutate(input_str):
        try:
            input_int = int(input_str)
            mutation_type = random.choice(['add', 'subtract', 'multiply', 'divide'])
            if mutation_type == 'add':
                mutated_int = input_int + random.randint(1, 10)
            elif mutation_type == 'subtract':
                mutated_int = input_int - random.randint(1, 10)
            elif mutation_type == 'multiply':
                mutated_int = input_int * random.randint(1, 10)
            else:
                denominator = random.randint(1, 10)
                mutated_int = input_int / denominator if denominator != 0 else input_int
            return canary + str(mutated_int) + canary
        except (ValueError, ZeroDivisionError):
            return input_str

    @staticmethod
    def _bitmask_mutate(input_str, mutation_rate):
        try:
            input_int = int(input_str)
            bitmask = random.randint(1, 255)
            mutated_int = input_int ^ bitmask
            return canary + str(mutated_int) + canary
        except ValueError:
            return input_str

    @staticmethod
    def _gen_rand_mutate(input_str, mutation_rate):
        mutated_str = ""
        for char in input_str:
            if random.random() < mutation_rate:
                mutated_str += random.choice(string.printable)
            else:
                mutated_str += char
        return canary + mutated_str + canary

    @staticmethod
    def _gen_rand_mutate_byte(input_str):
        mutated_str = ""
        for char in input_str:
            mutated_char = chr(ord(char) ^ random.randint(0, 255))
            mutated_str += mutated_char
        return canary + mutated_str + canary

    @staticmethod
    def _random_to_cyrillic(input_str, mutation_rate):
        cyrillic_str = ""
        for char in input_str:
            if char != "":  #avoid encoding whitespaces
                if random.random() < mutation_rate:
                    random_cyrillic_char = chr(random.randint(0x0410, 0x044F))
                    cyrillic_str += random_cyrillic_char
                else:
                    cyrillic_str += char

        cyrillic_encoded = quote(cyrillic_str, encoding='utf-8')

        return canary + cyrillic_encoded + canary

    @staticmethod
    def _add_weird_characters(input_str, mutation_rate):
        weird_characters = '|`~!\'"><&-\\?{}%;:][*@#$^)(/'
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                mutated_str = mutated_str[:i] + random.choice(weird_characters) + mutated_str[i+1:]

        return canary + mutated_str + canary
        
    @staticmethod
    def _add_html_tag_stripping(input_str):
        tag_stripping = ['>aa<', 'a>a<a"', 'a>><a', '<aa>', '<-aa->', '<abc>', '<!-aa-->', '<--aa-->', '<!--a->', '<!--zz-->', '<!--z-z-->', '<!-->z<-->', '&lt;', '&gt;', '&amp;']
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                random_strip = random.choice(tag_stripping)
                mutated_str = mutated_str[:i] + random_strip + mutated_str[i+1:]
                
        return canary + mutated_str + canary
        
    @staticmethod
    def _add_crlf(input_str):
        tag_stripping = ['%%0a0a', '%0a', '%Od%Oa', '%Od', '%23%Oa', '%23%Od%Oa', '%23%Od', '%25%30%61', '%25%30a', '%250a', '%25250a', '%2e%2e%2f%Od%Oa', '%2f%2e%2e%Od%Oa', '%2F..%Od%Oa', '%3f%Od%Oa', '%3f%Od', '%u000a']
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                random_strip = random.choice(tag_stripping)
                mutated_str = mutated_str[:i] + random_strip + mutated_str[i+1:]
                
        return canary + mutated_str + canary
        
    @staticmethod
    def _add_template_tag_stripping(input_str):
        tag_stripping = ['az{{%s', 'az${%"', 'az<#%s > ${%s}', 'a#setz', '#set', '{{=%s', '<%=', '<%', '#{%s', '{{=']
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                random_strip = random.choice(tag_stripping)
                mutated_str = mutated_str[:i] + random_strip + mutated_str[i+1:]
            
        return canary + mutated_str + canary

    @staticmethod
    def _add_random_bytes(input_str, mutation_rate):
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                random_byte = '\\x{:02x}'.format(random.randint(0, 255))
                mutated_str = mutated_str[:i] + random_byte + mutated_str[i+1:]

        return canary + mutated_str + canary

    @staticmethod
    def _add_raw_bytes(input_str, mutation_rate):
        raw_bytes = ''
        while random.random() < mutation_rate:
            random_byte = random.choice(string.printable)
            raw_bytes += random_byte
        return canary + input_str + raw_bytes + canary

    @staticmethod
    def _add_known_bad_escape_sequence(input_str):
        mutated_str = input_str
        bad_sequences = ['\\zz', '\\"', '\\$', '\\{', '\\x41', '\\(', '\\', '\\101', '\\0', '\\x0']
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                bad_sequence = random.choice(bad_sequences)
                mutated_str = mutated_str[:i] + bad_sequence + mutated_str[i+1:]
                
        return canary + mutated_str + canary

    @staticmethod
    def _add_random_unicode_characters(input_str, mutation_rate):
        unicode_char = ''
        mutated_str = input_str
        for i in range(len(mutated_str)):
            if mutated_str[i] != " " and random.random() < mutation_rate:
                unicode_char = chr(random.randint(0x1F600, 0x10FFFF))
                mutated_str = mutated_str[:i] + unicode_char + mutated_str[i+1:]
        
        return canary + mutated_str + canary

    @staticmethod
    def _add_unicode_escape_sequence(input_str, mutation_rate):
        unicode_char = ''
        while random.random() < mutation_rate:
            unicode_char += '\\u{:04x}'.format(random.randint(0, 0xFFFF))
        return canary + input_str + unicode_char + canary

    @staticmethod
    def _add_integer_division_by_zero(input_str):
        return canary + input_str + "1/0" + canary

    @staticmethod
    def _escape_sequence_unicode_mutate(input_str, mutation_rate):
        mutated_str = input_str
        while random.random() < mutation_rate:
            mutation_char = random.choice(['g', 'z'])
            unicode_char = '\\{}{:04x}'.format(mutation_char, random.randint(0, 0xFFFF))
            mutated_str += unicode_char
        return canary + mutated_str + canary

    @staticmethod
    def _regex_breakout_mutate(input_str, mutation_rate):
        mutated_str = input_str
        while random.random() < mutation_rate:
            mutation = random.choice(['z@', '\\\\@z@', 'z\\\\@', '\\\\@z\\\\@', '\\\\/z/', 'z\\\\/', '\\\\/z\\\\/', "\\\\z'", '\\\\z"', '\\\\"z@', '??', '*?', '+?', '|z', '.*', '.+', '()', '\\*', '\\+', '\\?', '\\.', '\\d', '[\\s\\S]', '[^\\w]', '\\d+$', 'abc(?=123)', 'xyz(?!789)', '(?<=\D)\d{3}'])
            mutated_str += mutation
        return canary + mutated_str + canary

    @staticmethod
    def _interpolation_mutate(input_str, mutation_rate):
        mutated_str = input_str
        while random.random() < mutation_rate:
            mutation = random.choice(['%{{z${{z', 'z%{{zz${{z', '$}}', '}}$z', 'z$}}z', '%{{41', '41%}}41', 'a%>s'])
            mutated_str += mutation
        return canary + mutated_str + canary

    @staticmethod
    def _divide_by_expression_mutate(input_str, mutation_rate):
        mutated_str = input_str
        while random.random() < mutation_rate:
            numerator = random.randint(1, 10)
            denominator = random.randint(1, 10)
            mutation = '/({}-{})'.format(numerator, denominator)
            mutated_str += mutation
        return canary + mutated_str + canary

    @staticmethod
    def _file_path_manipulation_mutate(input_str, mutation_rate):
        mutated_str = input_str
        while random.random() < mutation_rate:
            mutation = random.choice(['../', 'z/', '_/', './../', './cow/../', './foo/bar/../../', './z/../', '..\\z', '\\z\\..\\'])
            mutated_str += mutation
        return canary + mutated_str + canary

    def mutate_string(self, input_str):
        mutation_functions = [
            self._arithmetic_mutate,
            lambda c: self._random_to_cyrillic(c, self.mutation_rate),
            lambda s: self._add_weird_characters(s, self.mutation_rate),
            self._add_html_tag_stripping,
            self._add_crlf,
            self._add_template_tag_stripping,
            self._add_known_bad_escape_sequence,
            lambda q: self._add_random_unicode_characters(q, self.mutation_rate),
            lambda r: self._add_unicode_escape_sequence(r, self.mutation_rate),
            lambda u: self._escape_sequence_unicode_mutate(u, self.mutation_rate),
            lambda v: self._regex_breakout_mutate(v, self.mutation_rate),
            lambda x: self._interpolation_mutate(x, self.mutation_rate),
            lambda y: self._divide_by_expression_mutate(y, self.mutation_rate),
            lambda z: self._file_path_manipulation_mutate(z, self.mutation_rate)
        ]
        
        if fuzzer_engine == "essential":
            pass
        elif fuzzer_engine == "all":
            # Add more mutation rules
            mutation_functions += [
                lambda a: self._bitmask_mutate(a, self.mutation_rate),
                lambda b: self._gen_rand_mutate(b, self.mutation_rate),
                self._gen_rand_mutate_byte,
                lambda p: self._add_random_bytes(p, self.mutation_rate),
                lambda o: self._add_raw_bytes(o, self.mutation_rate)
            ]
        else:
            print("[-] Uknown value " + fuzzer_engine + ". The options are 'essential' or 'all'.")
            exit()

        mutated_strings = [input_str]
        mutated_input = ""

        for _ in range(self.max_mutations):
            for mutation_function in mutation_functions:
                if payload_complexity == "low":
                    # Mutate the raw payload only
                    mutated_input = input_str
                elif payload_complexity == "high":
                    # Take an already mutated payload and keep mutating it
                    mutated_input = random.choice(mutated_strings)
                mutated_strings.append(mutation_function(mutated_input))
                    
        # Remove elements from the array where the string isn't mutated
        filtered_mutated_array = [x for x in mutated_strings if x != input_str]
        
        # Remove duplicates
        filtered_mutated_array = list(set(filtered_mutated_array))
            
        return filtered_mutated_array
        
    @staticmethod
    def save_to_file(mutated_strings, output_file):
        with open(output_file, "a") as f:
            f.write("\n".join(mutated_strings))


def parse_config_file(filename):
    config = configparser.ConfigParser()
    config.read(filename)

    settings = {}

    # Read values from the 'Settings' section
    settings['canary'] = config.get('Settings', 'canary')
    settings['input_string'] = config.get('Settings', 'input_string')
    settings['fuzzer_engine'] = config.get('Settings', 'fuzzer_engine')
    settings['payload_complexity'] = config.get('Settings', 'payload_complexity')
    settings['mutation_rate'] = config.getfloat('Settings', 'mutation_rate')
    settings['max_mutations'] = config.getint('Settings', 'max_mutations')

    return settings
    
if __name__ == "__main__":
    print("[+] Reading the configuration file")

    config_filename = "config.ini"
    settings = parse_config_file(config_filename)

    canary = settings['canary']
    input_string = settings['input_string']
    fuzzer_engine = settings['fuzzer_engine']
    payload_complexity = settings['payload_complexity']
    mutation_rate = settings['mutation_rate']
    max_mutations = settings['max_mutations']
    
    print("[+] Configuration file successfully read")

    # Initialize the fuzzer
    print("[+] Initializing the fuzzer engine")
    fuzzer = Fuzzer(initial_seed=input_string, mutation_rate=mutation_rate, max_mutations=max_mutations)
    print("[+] Fuzzer started! Generating the mutated payloads")
    # Save the mutated payloads in an array
    mutated_strings = fuzzer.mutate_string(input_string)

    # Uncomment the following 2 lines, if you want to print the mutated strings when configuring the values (not recommended to copy the results)
    #for mutated_str in mutated_strings:
    #    print(mutated_str)

    # Uncomment the following line if you want to append the output to a file
    print("[+] Saving the mutated payloads in the txt file")
    fuzzer.save_to_file(mutated_strings, "mutations.txt")
    print("[+] Finished")

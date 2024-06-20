__int64 __fastcall quarantine_info_parse(const char *input_str, __int64 max_length, _DWORD *parsed_int, char *output_buf) {
    __int64 result; // Variable to store the return value
    __int64 semicolon_count; // Counter for semicolons found in the string
    const char *current_char; // Iterator for the input string
    size_t substring_length; // Length of the extracted substring
    __int64 parsed_long; // Extracted long value from the input string
    int parsed_status; // Extracted integer value from the input string

    // If parsed_int is not NULL, attempt to parse the initial integer and long values
    if (parsed_int) {
        parsed_status = 0; // Initialize the integer value
        parsed_long = 0LL; // Initialize the long value
        // Parse the input string for an integer (%04x) and a long (%08lx)
        if (sscanf(input_str, "%04x;%08lx", &parsed_status, &parsed_long) < 2)
            return 22LL; // Return error code 22 if parsing fails
        *parsed_int = parsed_status; // Store the parsed integer value in the provided pointer
    }

    // If output_buf is NULL, there's no need to extract a substring, return success
    if (!output_buf)
        return 0LL;

    // If max_length is zero, return error code 2 indicating invalid length
    if (!max_length)
        return 2LL;

    semicolon_count = 0LL; // Initialize the semicolon counter
    // Iterate through the input string to find the position after the second semicolon
    for (current_char = input_str + 1; ; ++current_char) {
        if (*(current_char - 1) == ';') // Check if the current character is a semicolon
            ++semicolon_count; // Increment the semicolon counter
        if (semicolon_count == 2) // Break the loop if the second semicolon is found
            break;
        if (!--max_length) // Return error code 2 if max_length reaches zero before finding the second semicolon
            return 2LL;
    }

    // Copy the substring starting after the second semicolon to output_buf
    strlcpy(output_buf, current_char, 0x100uLL);
    substring_length = strlen(current_char); // Calculate the length of the copied substring
    result = 0LL; // Set the return value to 0 indicating success
    output_buf[substring_length - 1] = '\0'; // Ensure the last character of output_buf is a null terminator
    return result; // Return the success code
}
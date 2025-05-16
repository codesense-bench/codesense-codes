krb5_error_code
ndr_dec_delegation_info(krb5_data *data, struct pac_s4u_delegation_info **out)
{ // L1 common_header_length=0, endianness=0, i=0, in=STRUCT, nservices=0, object_buffer_length=0, ret=109, version=0
    krb5_error_code ret;
    struct pac_s4u_delegation_info *di = NULL; // L3
    struct k5input in;
    uint32_t i, object_buffer_length, nservices;
    uint8_t version, endianness, common_header_length;
    *out = NULL; // L8
    di = k5alloc(sizeof(*di), &ret); // L10
    if (di == NULL) // L11 ret=0
        return ret;
    k5_input_init(&in, data->data, data->length); // L14
    version = k5_input_get_byte(&in); // L17
    endianness = k5_input_get_byte(&in); // L18 version=1
    common_header_length = k5_input_get_uint16_le(&in); // L19 endianness=16
    (void)k5_input_get_uint32_le(&in);  // L20 common_header_length=8
    if (version != 1 || endianness != 0x10 || common_header_length != 8) { // L21
        ret = EINVAL;
        goto error;
    }
    object_buffer_length = k5_input_get_uint32_le(&in); // L27
    if (data->length < 16 || object_buffer_length != data->length - 16) { // L28 object_buffer_length=93
        ret = EINVAL;
        goto error;
    }
    (void)k5_input_get_uint32_le(&in);  // L33
    (void)k5_input_get_uint32_le(&in); // L39
    (void)k5_input_get_uint16_le(&in); // L41
    (void)k5_input_get_uint16_le(&in); // L43
    (void)k5_input_get_uint32_le(&in); // L45
    (void)k5_input_get_uint32_le(&in); // L48
    (void)k5_input_get_uint32_le(&in); // L51
    ret = dec_wchar_pointer(&in, &di->proxy_target); // L53
    if (ret) // L54
        goto error;
    nservices = k5_input_get_uint32_le(&in); // L56
    if (nservices > data->length / 8) { // L60 nservices=1929405440
        ret = ERANGE; // L61
        goto error; // L62 ret=34
    }
    (void)k5_input_get_bytes(&in, 8 * nservices);
    di->transited_services = k5calloc(nservices + 1, sizeof(char *), &ret);
    if (di->transited_services == NULL)
        goto error;
    for (i = 0; i < nservices; i++) {
        ret = dec_wchar_pointer(&in, &di->transited_services[i]);
        if (ret)
            goto error;
        di->transited_services_length++;
    }
    ret = in.status;
    if (ret)
        goto error;
    *out = di;
    return 0;
error:
    ndr_free_delegation_info(di); // L86
    return ret; // L87
} // L88


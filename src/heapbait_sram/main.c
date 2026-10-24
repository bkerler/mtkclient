#include "dagent.h"
#include <string.h>

#define isdigit(c) ((c) >= '0' && (c) <= '9')
#define isxdigit(c)    (('0' <= (c) && (c) <= '9') || ('a' <= (c) && (c) <= 'f') || ('A' <= (c) && (c) <= 'F'))

#define CMD_FAIL(_error_msg, _status)   \
    do {                                \
        set_error_msg(_error_msg);       \
        status = _status;               \
        goto cmd_return;                \
    } while (0)

void safe_memcpy(void* dst, void* src, size_t len) {
    uint32_t* _dst = (uint32_t*)((uint64_t)dst & ~3);
    uint32_t* _src = (uint32_t*)((uint64_t)src & ~3);
    len >>= 2;
    while (len--) *_dst++ = *_src++;
}

static int hexval(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return 0;
}

unsigned long long atoull(const char *num) {
    unsigned long long value = 0;
    if (num[0] == '0' && num[1] == 'x') {
        // hex
        num += 2;
        while (*num && isxdigit(*num))
            value = value * 16 + hexval(*num++);
    } else {
        // decimal
        while (*num && isdigit(*num))
            value = value * 10 + *num++  - '0';
    }

    return value;
}

void split(char *src, char **dest, int *cnt, char sep) {
    if (!src || !dest || !cnt) {
        dprintf("Invalid parameters.\n");
        return;
    }
    int max = *cnt;
    if (max == 0)
        return;

    *cnt = 1;
    dest[0] = src;
    while (*src) {
        if (*src == sep) {
            *src = 0;
            if (*cnt >= max)
                return;
            dest[*cnt] = src + 1;
            ++(*cnt);
        }
      src++;
    }
}

size_t strnlen(char const *s, size_t count) {
	const char *sc = NULL;

	for(sc = s; count-- && *sc != '\0'; ++sc)
		;
	return sc - s;
}

mxml_type_t mxml_opaque_cb(mxml_node_t* node) {
    (void)node;
    return 2;
}

const char *mxmlGetNodeText(mxml_node_t *tree, const char *path) {
    mxml_node_t* node = mxmlFindPath(tree, path);
    if (node && node->type == 2) return node->value.opaque;
    return 0;
}

uint8_t memory_access_buf[0x1000];

int cmd_read_memory(struct com_channel_struct* channel, const char* xml) {
    dprintf("***Enter [%s] Cmd***\n", __FUNCTION__);
    if (!channel || !xml) {
        set_error_msg("Invalid parameters.");
        return 0xC0030007;
    }
    status_t status = 0;
    clear_error_msg();
    mxml_node_t* tree = mxmlLoadString(0, xml, mxml_opaque_cb);
    const char *_addr = 0, *_size = 0, *target_file = 0;
    if (!tree ||
        !(_addr = mxmlGetNodeText(tree, "da/arg/address")) ||
        !(_size = mxmlGetNodeText(tree, "da/arg/size")) ||
        !(target_file = mxmlGetNodeText(tree, "da/arg/target_file"))) {
        CMD_FAIL("Required XML node path not found. Check command string.", 0xC0010001);
    }
    void* addr = (void*)atoull(_addr);
    size_t size = atoull(_size);
    const char *cstr_cmd =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<host>"
        "<version>1.0</version>"
        "<command>CMD:UPLOAD-FILE</command>"
        "<arg><checksum>CHK_NO</checksum><info>%s</info><target_file>%s</"
        "target_file><packet_length>0x%x</packet_length></arg>"
        "</host>";
    char cmd_xml[1024];
    char *mxml_escape_file_name = mxml_escape(target_file, strnlen(target_file, 512));
    if (!mxml_escape_file_name)
        CMD_FAIL("mxml_escape failed.", 0xC0010013);
    unsigned int xml_len = _snprintf(cmd_xml, 1024, cstr_cmd, "memory", mxml_escape_file_name, 0x1000);
    if (xml_len >= 1024)
        CMD_FAIL("snprintf failed.", 0xC0010007);
    channel->write((uint8_t*)cmd_xml, xml_len + 1);
    char result[128];
    int result_len = 128;
    if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
        CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
    if (result[0] != 'O' || result[1] != 'K')
        CMD_FAIL("Host notice error.", 0xC0010001);
    channel->write((uint8_t*)result, _snprintf(result, 128, "OK@0x%x", size) + 1);
    result_len = 128;
    if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
        CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
    while (size) {
        channel->write((uint8_t*)"OK", 3);
        result_len = 128;
        if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
            CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
        size_t packet_size = size > 0x1000 ? 0x1000 : size;
        safe_memcpy(memory_access_buf, addr, packet_size);
        addr += packet_size;
        size -= packet_size;
        channel->write(memory_access_buf, packet_size);
        result_len = 128;
        if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
            CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
        if (result[0] != 'O' || result[1] != 'K')
            CMD_FAIL("Host notice error or user canceled.", 0xC0010001);
    }
cmd_return:
    if (tree) mxmlDelete(tree);
    return status;
}

int cmd_write_memory(struct com_channel_struct* channel, const char* xml) {
    dprintf("***Enter [%s] Cmd***\n", __FUNCTION__);
    if (!channel || !xml) {
        set_error_msg("Invalid parameters.\n");
        return 0xC0030007;
    }
    status_t status = 0;
    char write_started = 0;
    clear_error_msg();
    mxml_node_t* tree = mxmlLoadString(0, xml, mxml_opaque_cb);
    const char *_addr = 0, *_size = 0, *source_file = 0;
    if (!tree ||
        !(_addr = mxmlGetNodeText(tree, "da/arg/address")) ||
        !(_size = mxmlGetNodeText(tree, "da/arg/size")) ||
        !(source_file = mxmlGetNodeText(tree, "da/arg/source_file"))) {
        CMD_FAIL("Required XML node path not found. Check command string.", 0xC0010001);
    }
    void* addr = (void*)atoull(_addr);
    size_t size = atoull(_size);
    const char *cstr_cmd =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<host>"
        "<version>1.0</version>"
        "<command>CMD:DOWNLOAD-FILE</command>"
        "<arg><checksum>CHK_NO</checksum>"
        "<info>%s</info>"
        "<source_file>%s</source_file>"
        "<packet_length>0x%x</packet_length></arg>"
        "</host>";
    char cmd_xml[1024];
    char *mxml_escape_file_name = mxml_escape(source_file, strnlen(source_file, 512));
    if (!mxml_escape_file_name)
        CMD_FAIL("mxml_escape failed.", 0xC0010013);
    unsigned int xml_len = _snprintf(cmd_xml, 1024, cstr_cmd, "memory", mxml_escape_file_name, 0x1000);
    if (xml_len >= 1024)
        CMD_FAIL("snprintf failed.", 0xC0010007);
    channel->write((uint8_t*)cmd_xml, xml_len + 1);
    char result[128];
    int result_len = 128;
    if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
        CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
    if (result[0] != 'O' || result[1] != 'K')
        CMD_FAIL("Host notice error.", 0xC0010001);
    write_started = 1;
    result_len = 128;
    if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
        CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
    char *vec[2] = {0};
    int cnt = 2;
    split(result, vec, &cnt, '@');
    if (vec[0][0] != 'O' || vec[0][1] != 'K')
        CMD_FAIL("Host notice error.", 0xC0010001);
    size_t reported_size = atoull(vec[1]);
    if (reported_size > size)
        CMD_FAIL("Reported size is larger than requested.", 0xC0010001);
    size = reported_size;
    channel->write((uint8_t*)"OK", 3);
    while (size) {
        result_len = 128;
        if (channel->read((uint8_t*)result, (uint32_t*)&result_len))
            CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
        if (result[0] != 'O' || result[1] != 'K')
            CMD_FAIL("Host notice error or user canceled.", 0xC0010001);
        channel->write((uint8_t*)"OK", 3);
        uint32_t packet_size = size > 0x1000 ? 0x1000 : size;
        if (channel->read(memory_access_buf, &packet_size))
            CMD_FAIL("USB error or buffer is too small to contain all data.", 0xC0010001);
        safe_memcpy(addr, memory_access_buf, packet_size);
        addr += packet_size;
        size -= packet_size;
        channel->write((uint8_t*)"OK", 3);
    }
cmd_return:
    if (write_started && status) channel->write((uint8_t*)"ERR", 4);
    if (tree) mxmlDelete(tree);
    return status;
}

int cmd_execute_memory(struct com_channel_struct* channel, const char* xml) {
    dprintf("***Enter [%s] Cmd***\n", __FUNCTION__);
    if (!channel || !xml) {
        set_error_msg("Invalid parameters.\n");
        return 0xC0030007;
    }
    status_t status = 0;
    clear_error_msg();
    mxml_node_t* tree = mxmlLoadString(0, xml, mxml_opaque_cb);
    const char *_addr = 0, *_arg = 0;
    if (!tree ||
        !(_addr = mxmlGetNodeText(tree, "da/arg/address")) ||
        !(_arg = mxmlGetNodeText(tree, "da/arg/argument"))) {
        CMD_FAIL("Required XML node path not found. Check command string.", 0xC0010001);
    }
    status_t (*addr)(uint64_t) = (void*)atoull(_addr);
    uint64_t arg = atoull(_arg);
    status = addr(arg);
    if (status) set_error_msg("Error in executing memory.");
cmd_return:
    if (tree) mxmlDelete(tree);
    return status;
}

__attribute__((section(".text.start"))) void start() {
    dprintf("Hello world from sram@%x!", start);
    struct heap* theheap = (void*)dpc_chunk->node.next - __builtin_offsetof(struct heap, free_list);
    theheap->remaining -= dpc_chunk->len;
    dpc_chunk->node.prev->next = dpc_chunk->node.next;
    dpc_chunk->node.next->prev = dpc_chunk->node.prev;
    memset(dpc_chunk, 0, sizeof(*dpc_chunk));
    dprintf("theheap at 0x%x: base = 0x%x, len = 0x%x, remaining = 0x%x", theheap, theheap->base, theheap->len, theheap->remaining);
    register_major_command("CMD:READ-MEMORY", "1", cmd_read_memory);
    register_major_command("CMD:WRITE-MEMORY", "1", cmd_write_memory);
    register_major_command("CMD:EXECUTE-MEMORY", "1", cmd_execute_memory);
    return_addr();
}

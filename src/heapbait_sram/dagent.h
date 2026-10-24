#include <stdint.h>

typedef int status_t;

typedef uint64_t size_t;

struct com_channel_struct {
    status_t (*read)(uint8_t *buffer, uint32_t *length);
    status_t (*write)(uint8_t *buffer, uint32_t length);
    status_t (*log_to_pc)(const uint8_t *buffer, uint32_t length);
    status_t (*log_to_uart)(const uint8_t *buffer, uint32_t length);
};

typedef int (*HHANDLE)(struct com_channel_struct*c, const char* xml);

struct list_node {
    struct list_node *prev;
    struct list_node *next;
};

struct free_heap_chunk {
    struct list_node node;
    size_t len;
};

typedef struct wait_queue {
    int magic;
    struct list_node list;
    int count;
} wait_queue_t;

typedef struct mutex {
    uint32_t magic;
    void *holder;
    int count;
    wait_queue_t wait;
} mutex_t;

 struct heap {
    void *base;
    size_t len;
    size_t remaining;
    size_t low_watermark;
    mutex_t lock;
    struct list_node free_list;
};

typedef enum mxml_type_e		/**** The XML node type. ****/
{
  MXML_IGNORE = -1,			/* Ignore/throw away node @since Mini-XML 2.3@ */
  MXML_ELEMENT,				/* XML element with attributes */
  MXML_INTEGER,				/* Integer value */
  MXML_OPAQUE,				/* Opaque string */
  MXML_REAL,				/* Real value */
  MXML_TEXT,				/* Text fragment */
  MXML_CUSTOM				/* Custom data @since Mini-XML 2.1@ */
} mxml_type_t;

typedef void (*mxml_custom_destroy_cb_t)(void *);

typedef struct _mxml_attr_s		/**** An XML element attribute value. ****/
{
  char			*name;		/* Attribute name */
  char			*value;		/* Attribute value */
} _mxml_attr_t;

typedef struct _mxml_element_s		/**** An XML element value. ****/
{
  char			*name;		/* Name of element */
  int			num_attrs;	/* Number of attributes */
  _mxml_attr_t		*attrs;		/* Attributes */
} _mxml_element_t;

typedef struct _mxml_text_s		/**** An XML text value. ****/
{
  int			whitespace;	/* Leading whitespace? */
  char			*string;	/* Fragment string */
} _mxml_text_t;

typedef struct _mxml_custom_s		/**** An XML custom value. ****/
{
  void			*data;		/* Pointer to (allocated) custom data */
  mxml_custom_destroy_cb_t destroy;	/* Pointer to destructor function */
} _mxml_custom_t;

typedef union _mxml_value_u		/**** An XML node value. ****/
{
  _mxml_element_t	element;	/* Element */
  int			integer;	/* Integer number */
  char			*opaque;	/* Opaque string */
  double		real;		/* Real number */
  _mxml_text_t		text;		/* Text fragment */
  _mxml_custom_t	custom;		/* Custom data @since Mini-XML 2.1@ */
} _mxml_value_t;

struct _mxml_node_s			/**** An XML node. ****/
{
  mxml_type_t		type;		/* Node type */
  struct _mxml_node_s	*next;		/* Next node under same parent */
  struct _mxml_node_s	*prev;		/* Previous node under same parent */
  struct _mxml_node_s	*parent;	/* Parent node */
  struct _mxml_node_s	*child;		/* First child node */
  struct _mxml_node_s	*last_child;	/* Last child node */
  _mxml_value_t		value;		/* Node value */
  int			ref_count;	/* Use count */
  void			*user_data;	/* User data */
};

typedef struct _mxml_node_s mxml_node_t;

typedef mxml_type_t (*mxml_load_cb_t)(mxml_node_t *);

int (*dprintf)(const char *fmt, ...) = (void*)0x200251C;
int (*_snprintf)(char *str, size_t len, const char *fmt, ...) = (void*)0x2005254;
void (*register_major_command)(const char *str_id, const char *version, HHANDLE handle) = (void*)0x2003564;
void (*set_error_msg)(const char *fmt, ...) = (void*)0x2003154;
void (*clear_error_msg)() = (void*)0x2003114;
mxml_node_t* (*mxmlLoadString)(mxml_node_t *top, const char *s, mxml_load_cb_t cb) = (void*)0x20875D0;
mxml_node_t* (*mxmlFindPath)(mxml_node_t *top, const char *path) = (void*)0x2089300;
char* (*mxml_escape)(const char *src, uint32_t len) = (void*)0x20843D8;
void (*mxmlDelete)(mxml_node_t *node) = (void*)0x2088E48;
void (*return_addr)(void) = (void*)0x2003620;

struct free_heap_chunk* dpc_chunk = (void*)0x2101FF8;
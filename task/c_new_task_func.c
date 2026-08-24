#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mrubyc.h"

#if !defined(MRBC_MEMORY_SIZE)
#define MRBC_MEMORY_SIZE (1024*40)
#endif
static uint8_t memory_pool[MRBC_MEMORY_SIZE];



typedef struct TaskBytecodeEntry {
    mrbc_tcb *tcb;
    uint8_t *buf;
    size_t size;
    struct TaskBytecodeEntry *next;
} TaskBytecodeEntry;

static TaskBytecodeEntry *g_task_bytecodes;

static void task_bytecode_register(mrbc_tcb *tcb, uint8_t *buf,size_t size)
{
    TaskBytecodeEntry *e = (TaskBytecodeEntry *)mrbc_raw_alloc(sizeof(TaskBytecodeEntry));
    if( !e ) return;
    e->tcb= tcb;
    e->buf= buf;
    e->size= size;
    e->next = g_task_bytecodes;
    g_task_bytecodes= e;
}

static uint8_t *task_bytecode_unregister(mrbc_tcb *tcb, size_t *out_size)
{
    TaskBytecodeEntry **pp = &g_task_bytecodes;
    while( *pp ) {
        TaskBytecodeEntry *e = *pp;
        if( e->tcb== tcb ) {
            *pp= e->next;
            uint8_t *buf= e->buf;
            if( out_size ) *out_size= e->size;
            mrbc_raw_free(e);
            return buf;
        }
        pp = &((*pp)->next);
    }
    if( out_size ) *out_size = 0;
    return NULL;
}

uint8_t * load_mrb_file(const char *filename, size_t *out_size)
{
    FILE *fp= fopen(filename, "rb");
    
    if( fp== NULL ) {
        fprintf(stderr, "File␣not␣found␣(%s)\n", filename);
        return NULL;
    }


    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "fseek␣failed\n");
        fclose(fp);
        return NULL;
    }
    long lsize= ftell(fp);
    if (lsize < 0) {
        fprintf(stderr, "ftell␣failed\n");  
        fclose(fp);
        return NULL;
    }
    size_t size = (size_t)lsize;
    rewind(fp);


    uint8_t *p = (uint8_t *)malloc(size);
    if( p== NULL ) {
     fprintf(stderr, "Memory␣allocate␣error.\n");
     fclose(fp);
     return NULL;
    }
    size_t n= fread(p, 1, size, fp);
    if (n != size) {
        fprintf(stderr, "Read␣error:␣expected␣%zu␣bytes␣but␣got␣%zu\n", size, n);
        free(p);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    
    if (out_size) *out_size= size;
    return p;  
}


static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static size_t collect_child_ireps_raw(const mrbc_irep *irep,uint8_t **out_buf, size_t *out_size) {
    if (!irep || !irep->inst) {
        return 0;
    }

    const uint8_t *record_ptr = irep->inst - 12;
    record_ptr -= 4;
    uint32_t record_size = read_be32(record_ptr);

    if (record_size == 0) {
        return 0;
    }
    
    size_t total_bytes = record_size;
    for (uint16_t i = 0; i < irep->rlen; i++) {
        size_t child_size = 0;
        collect_child_ireps_raw(mrbc_irep_child_irep(irep, i), NULL, &child_size);
        total_bytes += child_size;
    }

    if (!out_buf) {
        if (out_size) *out_size = total_bytes;
        return total_bytes;
    }


    uint8_t *buf = (uint8_t *)mrbc_raw_alloc(total_bytes);
    if (!buf) {
        *out_buf = NULL;
        if (out_size) *out_size = 0;
        return 0;
    }

    size_t offset = 0;
    memcpy(buf + offset, record_ptr, record_size);
    offset += record_size;

    for (uint16_t i = 0; i < irep->rlen; i++) {
        uint8_t *child_buf = NULL;
        size_t child_size = 0;
        collect_child_ireps_raw(mrbc_irep_child_irep(irep, i), &child_buf, &child_size);
        if (!child_buf || child_size == 0) {
           if (child_buf) mrbc_raw_free(child_buf); 
           mrbc_raw_free(buf);
           *out_buf = NULL;
           if (out_size) *out_size = 0;
           return 0;
        }
        memcpy(buf + offset, child_buf, child_size);
        offset += child_size;
        mrbc_raw_free(child_buf);
    }

    *out_buf = buf;
    if (out_size) *out_size = total_bytes;
    return total_bytes;
}

static size_t collect_child_ireps(const mrbc_irep *irep, uint8_t**out_buf, size_t *out_size) {
    if (!irep || !irep->inst) {
      if (out_buf) *out_buf = NULL;
        if (out_size) *out_size = 0;
        return 0;
    }
    return collect_child_ireps_raw(irep, out_buf, out_size);
}

static uint8_t *wrap_irep_blob(uint8_t *irep_blob, size_t irep_blob_size, size_t *out_size) {
    if (!irep_blob || irep_blob_size == 0) {
        if (irep_blob) mrbc_raw_free(irep_blob); 
        if (out_size) *out_size = 0;
        return NULL;
    }

    static const char RITE_ID[4] = { 'R','I','T','E' };
    static const char RITE_VER[4] = { '0','3','0','0' };
    static const char COMPILER[4] = { 'M','A','T','Z' };
    static const char COMP_VER[4] = { '0','0','0','0' };
    static const char IREP_ID[4] = { 'I','R','E','P' };
    static const char IREP_VER[4] = { '0','3','0','0' };
    static const char END_ID[4] = { 'E','N','D','\0' };

    const size_t HEADER_RITE = 20;
    const size_t HEADER_IREP = 12;
    const size_t SECTION_END = 8;
    uint32_t irep_section_size = (uint32_t)(HEADER_IREP + irep_blob_size);
    uint32_t total_after_header = irep_section_size + SECTION_END;
    size_t file_size = HEADER_RITE + total_after_header;


    uint8_t *buf = (uint8_t *)mrbc_raw_alloc(file_size);
    if (!buf) {
        mrbc_raw_free(irep_blob);
        if (out_size) *out_size = 0;
        return NULL;
    }

    size_t off = 0;
    memcpy(buf + off, RITE_ID, sizeof(RITE_ID)); off += 4;
    memcpy(buf + off, RITE_VER, sizeof(RITE_VER)); off += 4;
    buf[off++] = (uint8_t)((total_after_header >> 24) & 0xff);
    buf[off++] = (uint8_t)((total_after_header >> 16) & 0xff);
    buf[off++] = (uint8_t)((total_after_header >> 8) & 0xff);
    buf[off++] = (uint8_t)(total_after_header & 0xff);
    memcpy(buf + off, COMPILER, sizeof(COMPILER)); off += 4;
    memcpy(buf + off, COMP_VER, sizeof(COMP_VER)); off += 4;

    memcpy(buf + off, IREP_ID, sizeof(IREP_ID)); off += 4;
    buf[off++] = (uint8_t)((irep_section_size >> 24) & 0xff);
    buf[off++] = (uint8_t)((irep_section_size >> 16) & 0xff);
    buf[off++] = (uint8_t)((irep_section_size >> 8) & 0xff);
    buf[off++] = (uint8_t)(irep_section_size & 0xff);
    memcpy(buf + off, IREP_VER, sizeof(IREP_VER)); off += 4;
    memcpy(buf + off, irep_blob, irep_blob_size); off +=irep_blob_size;

    memcpy(buf + off, END_ID, sizeof(END_ID)); off += 4;
    buf[off++] = (uint8_t)((SECTION_END >> 24) & 0xff);
    buf[off++] = (uint8_t)((SECTION_END >> 16) & 0xff);
    buf[off++] = (uint8_t)((SECTION_END >> 8) & 0xff);
    buf[off++] = (uint8_t)(SECTION_END & 0xff);

    mrbc_raw_free(irep_blob);
    if (out_size) *out_size = file_size;
    return buf;
}

static uint8_t *build_mrb_from_irep(const mrbc_irep *irep, size_t *out_size) {
    uint8_t *irep_blob = NULL;
    size_t irep_blob_size = 0;
    if (!collect_child_ireps(irep, &irep_blob, &irep_blob_size) ||!irep_blob) {
        if (out_size) *out_size = 0;
        return NULL;
    }
    return wrap_irep_blob(irep_blob, irep_blob_size, out_size);
}

static uint8_t *build_mrb_from_method_body(const mrbc_irep *irep,size_t *out_size) {
    if (!irep || !irep->inst) return NULL;

    const uint8_t *record_ptr = irep->inst - 12;
    record_ptr -= 4;
    uint32_t old_record_size = read_be32(record_ptr);

    const uint8_t *p = record_ptr + 4;
    uint16_t nlocals = read_be16(p); p += 2;
    uint16_t nregs = read_be16(p); p += 2;
    uint16_t rlen = read_be16(p); p += 2;
    uint16_t clen = read_be16(p); p += 2;
    uint32_t ilen = read_be32(p); p += 4;


    if (ilen < 4) {
        return NULL;
    }
    const uint8_t *inst_ptr = p;
    if (inst_ptr[0] != 0x34) {
       return NULL;
    }
    if (inst_ptr[1] != 0x00 || inst_ptr[2] != 0x00 || inst_ptr[3]!= 0x00) {

       return NULL;
    }
    
    
    uint32_t new_ilen = ilen - 4;

    size_t catch_bytes = (size_t)clen * 13;
    const uint8_t *catch_ptr = inst_ptr + ilen;
    const uint8_t *tail_ptr = catch_ptr + catch_bytes;
    if (16 + ilen + catch_bytes > old_record_size) {
        return NULL;
    }
    size_t tail_len = old_record_size - (16 + ilen + catch_bytes);


    uint32_t new_record_size = old_record_size - 4;
    uint8_t *root_record = (uint8_t *)mrbc_raw_alloc(new_record_size);
    if (!root_record) {
        return NULL;
    }

    uint8_t *w = root_record;
    w[0] = (uint8_t)((new_record_size >> 24) & 0xff);
    w[1] = (uint8_t)((new_record_size >> 16) & 0xff);
    w[2] = (uint8_t)((new_record_size >> 8) & 0xff);
    w[3] = (uint8_t)(new_record_size & 0xff);
    w += 4;


    w[0] = (uint8_t)(nlocals >> 8); w[1] = (uint8_t)(nlocals & 0xff); w += 2;
    w[0] = (uint8_t)(nregs >> 8); w[1] = (uint8_t)(nregs & 0xff);w += 2;
    w[0] = (uint8_t)(rlen >> 8); w[1] = (uint8_t)(rlen & 0xff); w+= 2;
    w[0] = (uint8_t)(clen >> 8); w[1] = (uint8_t)(clen & 0xff); w+= 2;
    w[0] = (uint8_t)((new_ilen >> 24) & 0xff);
    w[1] = (uint8_t)((new_ilen >> 16) & 0xff);
    w[2] = (uint8_t)((new_ilen >> 8) & 0xff);
    w[3] = (uint8_t)(new_ilen & 0xff);
    w += 4;


    memcpy(w, inst_ptr + 4, new_ilen);
    w += new_ilen;

    if (catch_bytes) {
        memcpy(w, catch_ptr, catch_bytes);
        w += catch_bytes;
    }

    memcpy(w, tail_ptr, tail_len);
    w += tail_len;

    if ((size_t)(w - root_record) != new_record_size) {
        mrbc_raw_free(root_record);
        return NULL;
    }

    size_t total_size = new_record_size;
    for (uint16_t i = 0; i < rlen; i++) {
        uint8_t *child_buf = NULL;
        size_t child_size = 0;
        if (!collect_child_ireps(mrbc_irep_child_irep(irep, i), &child_buf, &child_size) || !child_buf) {
            if (child_buf) mrbc_raw_free(child_buf);
            mrbc_raw_free(root_record);
            return NULL;
        }
        uint8_t *tmp = (uint8_t *)mrbc_raw_realloc(root_record,total_size + child_size);   
        if (!tmp) {
            mrbc_raw_free(child_buf);
            mrbc_raw_free(root_record);
            return NULL;
        }
        root_record = tmp;
        memcpy(root_record + total_size, child_buf, child_size);
        total_size += child_size;
        mrbc_raw_free(child_buf);
    }

    return wrap_irep_blob(root_record, total_size, out_size);
}




static void c_task_destroy(mrbc_vm *vm, mrbc_value v[], int argc)
{
    (void)argc;

    if( v[0].tt == MRBC_TT_CLASS ) {
        mrbc_raise(vm, MRBC_CLASS(ArgumentError), "destroy␣must␣be␣called␣on␣a␣task␣instance");
        return;
    }

    mrbc_tcb **ptcb = (mrbc_tcb **)v[0].instance->data;
    mrbc_tcb *tcb = ptcb ? *ptcb : NULL;
    if( tcb == NULL ) {

        SET_NIL_RETURN();
        return;
    }

    if( tcb->state != TASKSTATE_DORMANT ) {
        mrbc_raise(vm, 0, "task␣must␣be␣DORMANT␣(join␣before␣destroy)");
        return;
    }


    if( mrbc_delete_task(tcb) != 0 ) {
        mrbc_raise(vm, 0, "mrbc_delete_task␣failed");
        return;
    }


    size_t bc_size = 0;
    uint8_t *bc = task_bytecode_unregister(tcb, &bc_size);
    if( bc ) {
        mrbc_raw_free(bc);
    }


    mrbc_raw_free(tcb);
    *ptcb = NULL;


    return;
}


static void c_new_task_func(struct VM *vm, mrbc_value v[], int argc) {
    SET_NIL_RETURN();

    if (argc < 1) {
        console_printf("new_task:␣argument␣required␣(Symbol).\n");
        return;
    }

    if (mrbc_type(v[1]) != MRBC_TT_SYMBOL) {
        console_printf("new_task:␣argument␣must␣be␣a␣Symbol.\n");
        return;
    }

    const char *sym_name = mrbc_symid_to_str(v[1].sym_id);
    mrbc_sym sym = v[1].sym_id;

    mrbc_method method;
    if (mrbc_find_method(&method, MRBC_CLASS(Object), sym) == 0){
        console_printf("new_task:␣method␣not␣found:␣%s\n",sym_name);   
        return;
    }

    if (method.c_func) {
        console_printf("new_task:␣%s␣is␣a␣C␣method␣(no␣IREP).\n",sym_name);
        return;
    }

    mrbc_irep *irep = method.irep;
    if (!irep) {
        console_printf("new_task:␣%s␣has␣no␣IREP.\n", sym_name);
        return;
    }
    
    int regs_size = MAX_REGS_SIZE;
    if (argc >= 2) {
        if (mrbc_type(v[2]) != MRBC_TT_INTEGER) {
            console_printf("new_task:␣regs_size␣must␣be␣Integer␣if␣provided.\n");
            return;
        }
        regs_size = mrbc_integer(v[2]);
        if (regs_size <= 0) {
            console_printf("new_task:␣invalid␣regs_size␣%d.\n",regs_size);
            return;
        }
    }

   size_t mrb_size = 0;
    uint8_t *mrb_buf = build_mrb_from_method_body(irep, &mrb_size);
    if (!mrb_buf) {
        console_printf("new_task:␣build_mrb_from_method_body␣failed,␣fallback␣to␣full␣irep\n");
        mrb_buf = build_mrb_from_irep(irep, &mrb_size);
    }
    if (!mrb_buf) {
       console_printf("new_task:␣build_mrb_from_irep␣failed\n");
       return;
    }
    
    
    mrbc_tcb *tcb = mrbc_tcb_new(regs_size, TASKSTATE_DORMANT,MRBC_TASK_DEFAULT_PRIORITY);
    if (!tcb) {
        console_printf("new_task:␣mrbc_tcb_new␣failed\n");
        mrbc_raw_free(mrb_buf);
        return;
    }


    if (!mrbc_create_task(mrb_buf, tcb)) {
        console_printf("new_task:␣mrbc_create_task␣failed\n");
        mrbc_raw_free(mrb_buf);
        mrbc_raw_free(tcb);
        return;
    }
    task_bytecode_register(tcb, mrb_buf, mrb_size);

    mrbc_class *task_cls = mrbc_get_class_by_name("Task");
    if (!task_cls) {
        console_printf("new_task:␣Task␣class␣not␣found\n");
        mrbc_delete_task(tcb);
        uint8_t *bc = task_bytecode_unregister(tcb, NULL);
        if( bc ) mrbc_raw_free(bc);
        mrbc_raw_free(tcb);
        return;
    }

    mrbc_value task_obj = mrbc_instance_new(vm, task_cls, sizeof(mrbc_tcb *));
    if (task_obj.instance == NULL) {
        console_printf("new_task:␣mrbc_instance_new␣failed\n");
        mrbc_delete_task(tcb);
        uint8_t *bc = task_bytecode_unregister(tcb, NULL);
        if( bc ) mrbc_raw_free(bc);
        mrbc_raw_free(tcb);
        return;
    }

    *(mrbc_tcb **)task_obj.instance->data = tcb;

    SET_RETURN(task_obj);
}


int main(int argc, char *argv[])
{
    if( argc != 2 ) {
        printf("Usage:␣%s␣<xxxx.mrb>\n", argv[0]);
        return 1;
    }

    size_t mrb_size = 0;
    uint8_t *mrbbuf = load_mrb_file( argv[1], &mrb_size );
    if( mrbbuf == NULL ) return 1;


    mrbc_init(memory_pool, MRBC_MEMORY_SIZE);


    mrbc_class *task_cls_for_def = mrbc_define_class(0, "Task",MRBC_CLASS(Object));
    if (!task_cls_for_def) {
        fprintf(stderr, "mrbc_define_class(\"Task\")␣failed\n");
        free(mrbbuf);
        return 1;
    }
    mrbc_define_method(0, task_cls_for_def, "new_task",c_new_task_func);
    mrbc_define_method(0, task_cls_for_def, "destroy",c_task_destroy);


    if( !mrbc_create_task(mrbbuf, NULL) ) {
        fprintf(stderr, "mrbc_create_task␣failed\n");
        free(mrbbuf);
        return 1;
    }

    int ret = mrbc_run();


    free(mrbbuf);

    return ret == 1 ? 0 : ret;
}



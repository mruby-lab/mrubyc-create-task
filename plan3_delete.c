#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "mrubyc.h"

/*! @file
  @brief
  mruby bytecode loader.

  <pre>
  Copyright (C) 2015- Kyushu Institute of Technology.
  Copyright (C) 2015- Shimane IT Open-Innovation Center.

  This file is distributed under BSD 3-Clause License.

  </pre>
*/

/***** Feature test switches ************************************************/
/***** System headers *******************************************************/
//@cond
#include "vm_config.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
//@endcond

/***** Local headers ********************************************************/
#include "mrubyc.h"

/*! @file
  @brief
  Realtime multitask monitor for mruby/c

  <pre>
  Copyright (C) 2015- Kyushu Institute of Technology.
  Copyright (C) 2015- Shimane IT Open-Innovation Center.

  This file is distributed under BSD 3-Clause License.
  </pre>
*/

/***** Feature test switches ************************************************/
/***** System headers *******************************************************/
//@cond
#include "vm_config.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
//@endcond

/***** Local headers ********************************************************/
#include "mrubyc.h"

/***** Macros ***************************************************************/
#ifndef MRBC_SCHEDULER_EXIT
#define MRBC_SCHEDULER_EXIT 0
#endif

#define VM2TCB(p) ((mrbc_tcb *)((uint8_t *)p - offsetof(mrbc_tcb, vm)))
#define MRBC_MUTEX_TRACE(...) ((void)0)


/***** Typedefs *************************************************************/
/***** Function prototypes **************************************************/
/***** Local variables ******************************************************/
#define NUM_TASK_QUEUE 4
static mrbc_tcb *task_queue_[NUM_TASK_QUEUE];
#define q_dormant_   (task_queue_[0])
#define q_ready_     (task_queue_[1])
#define q_waiting_   (task_queue_[2])
#define q_suspended_ (task_queue_[3])
static volatile uint32_t tick_;
static volatile uint32_t wakeup_tick_ = (1 << 16); // no significant meaning.


/***** Global variables *****************************************************/
/***** Signal catching functions ********************************************/
/***** Functions ************************************************************/
//================================================================
/*! Insert task(TCB) to task queue

  @param  p_tcb	Pointer to target TCB

  Put the task (TCB) into a queue by each state.
  TCB must be free. (must not be in another queue)
  The queue is sorted in priority_preemption order.
  If the same priority_preemption value is in the TCB and queue,
  it will be inserted at the end of the same value in queue.
*/


//================================================================
/*! Delete task(TCB) from task queue

  @param  p_tcb	Pointer to target TCB
*/



//================================================================
/*! preempt running task
*/
inline static void preempt_running_task(void)
{
  for( mrbc_tcb *t = q_ready_; t != NULL; t = t->next ) {
    if( t->state == TASKSTATE_RUNNING ) t->vm.flag_preemption = 1;
  }
}


//================================================================
/*! Tick timer interrupt handler.

*/
#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
EMSCRIPTEN_KEEPALIVE
#endif


//================================================================
/*! create (allocate) TCB.

  @param  regs_size	num of allocated registers.
  @param  task_state	task initial state.
  @param  priority	task priority.
  @return pointer to TCB or NULL.

<b>Code example</b>
@code
  //  If you want specify default value, see below.
  //    regs_size:  MAX_REGS_SIZE (in vm_config.h)
  //    task_state: MRBC_TASK_DEFAULT_STATE
  //    priority:   MRBC_TASK_DEFAULT_PRIORITY
  mrbc_tcb *tcb;
  tcb = mrbc_tcb_new( MAX_REGS_SIZE, MRBC_TASK_DEFAULT_STATE, MRBC_TASK_DEFAULT_PRIORITY );
  mrbc_create_task( byte_code, tcb );
@endcode
*/


//================================================================
/*! Create a task specifying bytecode to be executed.

  @param  byte_code	pointer to VM byte code.
  @param  tcb		Task control block with parameter, or NULL.
  @return Pointer to mrbc_tcb or NULL.
*/



//================================================================
/*! Delete a task.

  @param  tcb		Task control block.
  @return Pointer to mrbc_tcb or NULL.
*/


/***** Constat values *******************************************************/
// for mrb file structure.
static const char RITE[4] = "RITE";
static const char RITE_VERSION[4] = "0400";
static const int SIZE_RITE_BINARY_HEADER = 20;
static const int SIZE_RITE_SECTION_HEADER = 12;
static const int SIZE_RITE_CATCH_HANDLER = 13;
static const char IREP[4] = "IREP";
static const char END[4] = "END\0";


/*! IREP TT */
enum irep_pool_type {
  IREP_TT_STR   = 0,	// string (need free)
  IREP_TT_SSTR  = 2,	// string (static)
  IREP_TT_INT32 = 1,	// 32bit integer
  IREP_TT_INT64 = 3,	// 64bit integer
  IREP_TT_FLOAT = 5,	// float (double/float)
};


/***** Macros ***************************************************************/
/***** Typedefs *************************************************************/
/***** Function prototypes **************************************************/
/***** Local variables ******************************************************/
/***** Global variables *****************************************************/
/***** Signal catching functions ********************************************/
/***** Local functions ******************************************************/

//================================================================
/*! Parse header section.

  @param  vm    A pointer to VM.
  @param  bin	A pointer to RITE header.
  @return int	zero if no error.

  <pre>
  Structure
   "RITE"     identifier
   "03"       major version
   "00"       minor version
   0000_0000  total size
   "MATZ"     compiler name
   "0000"     compiler version
  </pre>
*/
static int load_header(struct VM *vm, const uint8_t *bin)
{
  if( memcmp(bin, RITE, sizeof(RITE)) != 0 ) {
    mrbc_raise( vm, MRBC_CLASS(Exception), "Illegal bytecode");
    return -1;
  }
  bin += sizeof(RITE);

  if( memcmp(bin, RITE_VERSION, sizeof(RITE_VERSION)) != 0 ) {
    mrbc_raise( vm, MRBC_CLASS(Exception), "Bytecode version mismatch");
    return -1;
  }

  /* Ignore others. */

  return 0;
}


//================================================================
/*! read one irep section.

  @param  vm	A pointer to VM.
  @param  bin	A pointer to RITE ISEQ.
  @param  len	Returns the parsed length.
  @return	Pointer to allocated mrbc_irep or NULL

  <pre>
   (loop n of child irep below)
   0000_0000	record size
   0000		n of local variable
   0000		n of register
   0000		n of child irep
   0000		n of catch handler
   0000_0000	n of byte code  (ISEQ BLOCK)
   ...		byte codes

   (CATCH HANDLER 13bytes)
   00		type
   0000_0000	begin
   0000_0000	end
   0000_0000	target

   (POOL BLOCK)
   0000		n of pool
   (loop n of pool)
     00		type
     ...	pool data

   (SYMS BLOCK)
   0000		n of symbol
   (loop n of symbol)
     0000	length
     ...	symbol data
  </pre>
*/
static mrbc_irep * load_irep_1(struct VM *vm, const uint8_t *bin, int *len)
{
  mrbc_irep irep;
  const uint8_t *p = bin + 4;	// 4 = skip record size.

#if defined(MRBC_DEBUG)
  irep.obj_mark_[0] = 'R';	// set "RP"
  irep.obj_mark_[1] = 'P';
#endif

  irep.ref_count = 0;
#if defined(MRBC_DEBUG)
  irep.nlocals = bin_to_uint16(p);	p += 2;
#else
  p += 2;	// skip nlocals
#endif
  irep.nregs = bin_to_uint16(p);	p += 2;
  irep.rlen = bin_to_uint16(p);		p += 2;
  irep.clen = bin_to_uint16(p);		p += 2;
  uint32_t ilen = bin_to_uint32(p);	p += 4;
  if( ilen > 0xffff ) goto ERROR_TOO_LARGE;
  irep.ilen = ilen;
  irep.inst = p;

  // POOL block
  p += irep.ilen + SIZE_RITE_CATCH_HANDLER * irep.clen;
  irep.pool = p;
  uint16_t plen = bin_to_uint16(p);	p += 2;

  // skip pool
  for( int i = 0; i < plen; i++ ) {
    int siz = 0;
    int tt = *p++;

    switch( tt ) {
    case IREP_TT_STR:
    case IREP_TT_SSTR:	siz = bin_to_uint16(p) + 3;	break;
    case IREP_TT_INT32:	siz = 4;	break;
    case IREP_TT_INT64:
#if !defined(MRBC_INT64)
      mrbc_raise(vm, MRBC_CLASS(NotImplementedError), "Unsupported int64 (set MRBC_INT64 in vm_config)");
#endif
    case IREP_TT_FLOAT:	siz = 8;	break;
    default:
      mrbc_raisef(vm, MRBC_CLASS(Exception), "Not support such type (IREP_TT=%d)", tt);
      return NULL;
    }
    p += siz;
  }

  // num of symbols, offset of tbl_ireps.
  uint16_t slen = bin_to_uint16(p);	p += 2;
  uint32_t siz = sizeof(mrbc_sym) * slen;
  if( siz > 0xffff ) goto ERROR_TOO_LARGE;
  irep.ofs_pools = siz;

  siz += sizeof(uint16_t) * plen;
  if( siz > 0xffff ) goto ERROR_TOO_LARGE;
  siz += (-siz & 0x03);	// padding. 32bit align.
  irep.ofs_ireps = siz;

#if defined(MRBC_DEBUG)
  irep.plen = plen;
  irep.slen = slen;
#endif

  // allocate new irep
  siz = sizeof(mrbc_irep) + siz + sizeof(mrbc_irep*) * irep.rlen;
  mrbc_irep *p_irep = mrbc_raw_alloc( siz );
  if( !p_irep ) {	// ENOMEM
    mrbc_raise(vm, MRBC_CLASS(NoMemoryError),0);
    return NULL;
  }
  *p_irep = irep;

  // make a symbol ID table. (tbl_syms[slen])
  mrbc_sym *tbl_syms = mrbc_irep_tbl_syms(p_irep);
  for( int i = 0; i < slen; i++ ) {
    int siz = bin_to_uint16(p) + 1;	p += 2;
    char *sym_str;
    if (vm->flag_permanence == 1) {
      sym_str = mrbc_raw_alloc_no_free(siz);
      memcpy(sym_str, p, siz);
    } else {
      sym_str = (char *)p;
    }
    mrbc_sym sym = mrbc_str_to_symid( sym_str );
    if( sym < 0 ) {
      mrbc_raise(vm, MRBC_CLASS(Exception), "Overflow MAX_SYMBOLS_COUNT");
      return NULL;
    }
    *tbl_syms++ = sym;
    p += (siz);
  }

  // make a pool data's offset table. (tbl_pools[plen])
  uint16_t *ofs_pools = mrbc_irep_tbl_pools(p_irep);
  p = p_irep->pool + 2;
  for( int i = 0; i < plen; i++ ) {
    int siz = 0;
    if( (p - irep.pool) > UINT16_MAX ) {
      mrbc_raise(vm, MRBC_CLASS(Exception), "Overflow IREP data offset table");
      return NULL;
    }
    *ofs_pools++ = (uint16_t)(p - irep.pool);
    switch( *p++ ) {
    case IREP_TT_STR:
    case IREP_TT_SSTR:	siz = bin_to_uint16(p) + 3;  break;
    case IREP_TT_INT32:	siz = 4;  break;
    case IREP_TT_INT64:
    case IREP_TT_FLOAT:	siz = 8;  break;
    }
    p += siz;
  }

  // return length
  *len = bin_to_uint32(bin);
  return p_irep;


 ERROR_TOO_LARGE:
  mrbc_raise(vm, MRBC_CLASS(Exception), "Too large IREP size");
  return NULL;
}


//================================================================
/*! Load IREP section.

  @param  vm	A pointer to VM.
  @param  bin	A pointer to RITE ISEQ.
  @param  len	Returns the parsed length.
  @return	Pointer to allocated mrbc_irep or NULL
*/
static mrbc_irep *load_irep(struct VM *vm, const uint8_t *bin, int *len)
{
  int len1;
  mrbc_irep *irep = load_irep_1(vm, bin, &len1);
  if( !irep ) return NULL;
  int total_len = len1;

  mrbc_irep **tbl_ireps = mrbc_irep_tbl_ireps(irep);

  for( int i = 0; i < irep->rlen; i++ ) {
    tbl_ireps[i] = load_irep(vm, bin + total_len, &len1);
    if( ! tbl_ireps[i] ) return NULL;
    total_len += len1;
  }

  if( len ) *len = total_len;
  return irep;
}


/***** Global functions *****************************************************/

//================================================================
/*! Load the VM bytecode. (full .mrb file)

  @param  vm		Pointer to VM.
  @param  bytecode	Pointer to bytecode.
  @return int		zero if no error.
*/
int mrbc_load_mrb(struct VM *vm, const void *bytecode)
{
  const uint8_t *bin = bytecode;

  vm->exception = mrbc_nil_value();
  if( load_header(vm, bin) != 0 ) return -1;

  bin += SIZE_RITE_BINARY_HEADER;

  while( 1 ) {
    if( memcmp(bin, IREP, sizeof(IREP)) == 0 ) {
      if( mrbc_load_irep( vm, bin ) != 0 ) break;

    } else if( memcmp(bin, END, sizeof(END)) == 0 ) {
      break;
    }
    // ignore other section.

    bin += bin_to_uint32(bin+4);	// add section size, to next section.
  }

  return mrbc_israised(vm);
}


//================================================================
/*! Load the IREP section.

  @param  vm		Pointer to VM.
  @param  bytecode	Pointer to IREP section.
  @return int		zero if no error.
*/
int mrbc_load_irep(struct VM *vm, const void *bytecode)
{
  const uint8_t *bin = bytecode;

  vm->top_irep = load_irep( vm, bin + SIZE_RITE_SECTION_HEADER, 0 );
  if( vm->top_irep == NULL ) return -1;

  return mrbc_israised(vm);
}


//================================================================
/*! release mrbc_irep holds memory

  @param  irep	Pointer to allocated mrbc_irep.
*/
void mrbc_irep_free(struct IREP *irep)
{
  // release child ireps.
  for( int i = 0; i < irep->rlen; i++ ) {
    mrbc_irep_free( mrbc_irep_child_irep(irep, i) );
  }

  if( irep->ref_count == 0 ) {
    mrbc_raw_free( irep );
  }
}


//================================================================
/*! get a mrbc_value in irep pool.

  @param  vm		Pointer to VM.
  @param  n		n'th
  @return mrbc_value	value
*/
mrbc_value mrbc_irep_pool_value(struct VM *vm, int n)
{
  const uint8_t *p = mrbc_irep_pool_ptr(vm->cur_irep, n);
  mrbc_value obj;

  int tt = *p++;
  switch( tt ) {
#if MRBC_USE_STRING
  case IREP_TT_STR:
  case IREP_TT_SSTR: {
    int len = bin_to_uint16(p);
    obj = mrbc_string_new( vm, p+2, len );
    break;
  }
#endif

  case IREP_TT_INT32:
    mrbc_set_integer(&obj, bin_to_uint32(p));
    break;

#if MRBC_USE_FLOAT
  case IREP_TT_FLOAT:
    mrbc_set_float(&obj, bin_to_double64(p));
    break;
#endif

#if defined(MRBC_INT64)
  case IREP_TT_INT64:
    mrbc_set_integer(&obj, bin_to_int64(p));
    break;
#endif

  default:
    mrbc_raisef(vm, MRBC_CLASS(Exception), "Not support such type (IREP_TT=%d)", tt);
    mrbc_set_nil(&obj);
  }

  return obj;
}


#if !defined(MRBC_MEMORY_SIZE)
#define MRBC_MEMORY_SIZE (1024*40)
#endif
static uint8_t memory_pool[MRBC_MEMORY_SIZE];


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


    mrbc_raw_free(tcb);
    *ptcb = NULL;


    return;
}




int mrbc_load_irep_direct(struct VM *vm, mrbc_irep *irep_blob)
{

  vm->top_irep = irep_blob;
  if( vm->top_irep == NULL ) return -1;

  return mrbc_israised(vm);
}

int mrbc_load_mrb_direct(struct VM *vm, mrbc_irep *irep_blob)
{

  vm->exception = mrbc_nil_value();
   mrbc_load_irep_direct( vm, irep_blob );

  return mrbc_israised(vm);
}

mrbc_tcb * mrbc_create_task_direct(mrbc_irep *irep_blob, mrbc_tcb *tcb)
{
  if( !tcb ) tcb = mrbc_tcb_new( MAX_REGS_SIZE, MRBC_TASK_DEFAULT_STATE, MRBC_TASK_DEFAULT_PRIORITY );
  if( !tcb ) return NULL;	// ENOMEM

  tcb->priority_preemption = tcb->priority;

  // assign VM ID
  if( mrbc_vm_open( &tcb->vm ) == NULL ) {
    mrbc_printf("Error: Can't assign VM-ID.\n");
    return NULL;
  }

  if( mrbc_load_mrb_direct(&tcb->vm, irep_blob) != 0 ) {
    mrbc_print_vm_exception( &tcb->vm );
    mrbc_vm_close( &tcb->vm );
    return NULL;
  }
  mrbc_vm_begin( &tcb->vm );

  mrbc_hal_disable_irq();
  mrbc_task_q_insert(tcb);
  if( tcb->state & TASKSTATE_READY ) preempt_running_task();
  mrbc_hal_enable_irq();

  return tcb;
}

void operand_delete(mrbc_irep *irep)
{
  irep->ilen-=4;
  irep->inst+=4;
}

static void c_new_task_func_direct(struct VM *vm, mrbc_value v[], int argc) {
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





    if (!method.irep) {
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
    
    
    mrbc_tcb *tcb = mrbc_tcb_new(regs_size, TASKSTATE_DORMANT,MRBC_TASK_DEFAULT_PRIORITY);
    if (!tcb) {
        console_printf("new_task:␣mrbc_tcb_new␣failed\n");
        return;
    }


    if (!mrbc_create_task_direct(method.irep, tcb)) {
        console_printf("new_task:␣mrbc_create_task␣failed\n");
        mrbc_raw_free(tcb);
        return;
    }

    mrbc_class *task_cls = mrbc_get_class_by_name("Task");
    if (!task_cls) {
        console_printf("new_task:␣Task␣class␣not␣found\n");
        mrbc_delete_task(tcb);
        mrbc_raw_free(tcb);
        return;
    }

    mrbc_value task_obj = mrbc_instance_new(vm, task_cls, sizeof(mrbc_tcb *));
    if (task_obj.instance == NULL) {
        console_printf("new_task:␣mrbc_instance_new␣failed\n");
        mrbc_delete_task(tcb);
        mrbc_raw_free(tcb);
        return;
    }

    *MRBC_INSTANCE_DATA_PTR( &task_obj, mrbc_tcb *) = tcb;

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
    mrbc_define_method(0, task_cls_for_def, "destroy",c_task_destroy);
    mrbc_define_method(0, task_cls_for_def, "direct_new_task",c_new_task_func_direct);


    if( !mrbc_create_task(mrbbuf, NULL) ) {
        fprintf(stderr, "mrbc_create_task␣failed\n");
        free(mrbbuf);
        return 1;
    }

    int ret = mrbc_run();


    free(mrbbuf);

    return ret == 1 ? 0 : ret;
}



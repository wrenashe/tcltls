/*
 *  Copyright (C) 1997-2000 Matt Newman <matt@novadigm.com>
 *
 * Stylized option processing - requires consistent
 * external vars: opt, idx, objc, objv
 */

#ifndef _TCL_OPTS_H
#define _TCL_OPTS_H

#define OPT_PROLOG(option)			\
    if (strcmp(opt, (option)) == 0) {		\
	if (++idx >= objc) {			\
	    Tcl_AppendResult(interp,		\
		"no argument given for ",	\
		(option), " option",		\
		(char *) NULL);			\
	    return TCL_ERROR;			\
	}
#define OPT_POSTLOG()				\
	continue;				\
    }
#define OPTOBJ(option, var)			\
    OPT_PROLOG(option)				\
    var = objv[idx];				\
    OPT_POSTLOG()

#define OPTSTR(option, var)			\
    OPT_PROLOG(option)				\
    var = Tcl_GetString(objv[idx]);\
    OPT_POSTLOG()

#define OPTINT(option, var)			\
    OPT_PROLOG(option)				\
    if (Tcl_GetIntFromObj(interp, objv[idx],	\
	    &(var)) != TCL_OK) {		\
	    return TCL_ERROR;			\
    }						\
    OPT_POSTLOG()

#define OPTBOOL(option, var)			\
    OPT_PROLOG(option)				\
    if (Tcl_GetBooleanFromObj(interp, objv[idx],\
	    &(var)) != TCL_OK) {		\
	    return TCL_ERROR;			\
    }						\
    OPT_POSTLOG()

#define OPTBYTE(option, var, lvar)		\
    OPT_PROLOG(option)				\
    var = Tcl_GetByteArrayFromObj(objv[idx], &(lvar));\
    OPT_POSTLOG()

#define OPTBAD(type, list)			\
    Tcl_AppendResult(interp, "bad ", (type),	\
		" \"", opt, "\": must be ",	\
		(list), (char *) NULL)

/*
 * Convenient option processing macros used by cryptography modules
 */

#define GET_OPT_BOOL(objPtr, varPtr) \
    if (Tcl_GetBooleanFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_INT(objPtr, varPtr) \
    if (Tcl_GetIntFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_LONG(objPtr, varPtr) \
    if (Tcl_GetLongFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_WIDE(objPtr, varPtr) \
    if (Tcl_GetWideIntFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_BIGNUM(objPtr, varPtr) \
    if (Tcl_GetBignumFromObj(interp, objPtr, varPtr) != TCL_OK) {	\
	return TCL_ERROR;					\
    }

#define GET_OPT_STRING(objPtr, var, lenPtr) \
    if ((var = Tcl_GetStringFromObj(objPtr, lenPtr)) == NULL) {	\
	return TCL_ERROR;					\
    }								\

#define GET_OPT_BYTE_ARRAY(objPtr, var, lenPtr) \
    if ((var = Tcl_GetByteArrayFromObj(objPtr, lenPtr)) == NULL) {	\
	return TCL_ERROR;					\
    }								\

#endif /* _TCL_OPTS_H */

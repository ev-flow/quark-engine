# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.
# Thanks for the description of Dalvik bytecode instruction from the following
# websites, some of our explanations or comments will quote from it.
# https://source.android.google.cn/devices/tech/dalvik/instruction-formats
# http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html

import logging
from datetime import datetime

from quark import config
from quark.core.struct.registerobject import RegisterObject
from quark.core.struct.tableobject import TableObject

MAX_REG_COUNT = 40
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
if config.DEBUG:
    TIMESTAMPS = datetime.now().strftime("%Y-%m-%d")
    LOG_FILENAME = f"{TIMESTAMPS}.quark.log"
    handler = logging.FileHandler(LOG_FILENAME, mode="w")
    format_str = "%(asctime)s %(levelname)s [%(lineno)d]: %(message)s"
    handler.setFormatter(logging.Formatter(format_str))
    log.addHandler(handler)
else:
    log.disabled = True


def logger(func):
    def warp(*args, **kwargs):
        log.info(f"{func.__name__} with args-> {args}")

        func(*args, **kwargs)

    return warp


class PyEval:
    def __init__(self, apkinfo):
        # Main switch for executing the bytecode instruction.
        self.eval = {
            # invoke-kind
            "invoke-virtual": self.INVOKE_VIRTUAL,
            "invoke-virtual/range": self.INVOKE_VIRTUAL,
            "invoke-direct": self.INVOKE_DIRECT,
            "invoke-direct/range": self.INVOKE_DIRECT,
            "invoke-static": self.INVOKE_STATIC,
            "invoke-static/range": self.INVOKE_STATIC,
            "invoke-interface": self.INVOKE_INTERFACE,
            "invoke-interface/range": self.INVOKE_INTERFACE,
            "invoke-super": self.INVOKE_SUPER,
            "invoke-super/range": self.INVOKE_SUPER,
            "invoke-polymorphic": self.INVOKE_POLYMORPHIC,
            "invoke-polymorphic/range": self.INVOKE_POLYMORPHIC,
            "invoke-custom": self.INVOKE_CUSTOM,
            "invoke-custom/range": self.INVOKE_CUSTOM,
            # move-result-kind
            "move-result": self.MOVE_RESULT,
            "move-result-wide": self.MOVE_RESULT_WIDE,
            "move-result-object": self.MOVE_RESULT_OBJECT,
            # instance-kind
            "new-instance": self.NEW_INSTANCE,
            "new-array": self.NEW_ARRAY,
            # const-kind
            "const-string": self.CONST_STRING,
            "const-string/jumbo": self.CONST_STRING,
            "const-class": self.CONST_CLASS,
            "const": self.CONST,
            "const/4": self.CONST_FOUR,
            "const/16": self.CONST_SIXTEEN,
            "const/high16": self.CONST_HIGHSIXTEEN,
            "const-wide": self.CONST_WIDE,
            "const-wide/16": self.CONST_WIDE_SIXTEEN,
            "const-wide/32": self.CONST_WIDE_THIRTY_TWO,
            "const-wide/high16": self.CONST_WIDE_HIGHSIXTEEN,
        }

        # move-kind
        for prefix in ("move", "move-object", "move-wide"):
            for postfix in ("", "/from16", "/16"):
                self.eval[f"{prefix}{postfix}"] = self.MOVE_KIND
        self.eval["array-length"] = self.MOVE_KIND

        # filled-array-kind
        for ins in ("filled-new-array", "filled-new-array/range"):
            self.eval[ins] = self.FILLED_NEW_ARRAY_KIND

        # aget-kind
        for postfix in ("", "-object", "-boolean", "-byte", "-char", "-short"):
            self.eval[f"aget{postfix}"] = self.AGET_KIND
            self.eval["aget-wide"] = self.AGET_WIDE_KIND

        # aput-kind
        for postfix in ("", "-object", "-boolean", "-byte", "-char", "-short"):
            self.eval[f"aput{postfix}"] = self.APUT_KIND
            self.eval["aput-wide"] = self.APUT_WIDE_KIND

        # neg-kind and not-kind
        for prefix in ("neg", "not"):
            self.eval[f"{prefix}-int"] = self.NEG_AND_NOT_KIND
            self.eval[f"{prefix}-long"] = self.NEG_AND_NOT_KIND
            self.eval[f"{prefix}-float"] = self.NEG_AND_NOT_KIND
            self.eval[f"{prefix}-double"] = self.NEG_AND_NOT_KIND

        # type casting
        for first_type in ("int", "long", "float", "double"):
            for second_type in ("int", "long", "float", "double"):
                if first_type == second_type:
                    continue
                self.eval[f"{first_type}-{second_type}"] = self.CAST_TYPE

        # binop_kind
        for prefix in (
            "add",
            "sub",
            "mul",
            "div",
            "rem",
            "and",
            "or",
            "xor",
            "shl",
            "shr",
            "ushr",
        ):
            for _type in ("int", "float", "double", "long"):
                for postfix in ("", "/2addr", "/lit16", "/lit8"):
                    self.eval[f"{prefix}-{_type}{postfix}"] = self.BINOP_KIND

        self.eval["move-exception"] = lambda ins: self._assign_value(
            (ins[0], ins[1], "Exception"), value_type="Ljava/lang/Throwable;"
        )
        self.eval[
            "fill-array-data"
        ] = lambda ins: self._move_value_and_data_to_register(
            (ins[0], ins[1], ins[1], ins[2]), "Embedded-array-data()["
        )

        self.type_mapping = {
            "boolean": "Z",
            "byte": "B",
            "char": "C",
            "short": "S",
            "int": "I",
            "long": "J",
            "float": "F",
            "double": "D",
        }

        self.table_obj = TableObject(MAX_REG_COUNT)
        self.ret_stack = []
        self.ret_type = ""
        self.apkinfo = apkinfo

    def _invoke(self, instruction, look_up=False, skip_self=False):
        """
        Function call in Android smali code. It will check if the corresponding table field has a value, if it does,
        inserts its own function name into called_by_func column.
        """

        if look_up:
            try:
                instruction[-1] = self._lookup_implement(
                    self.table_obj.pop(int(instruction[1][1:])).current_type,
                    instruction[-1],
                    skip_self=skip_self,
                )
            except ValueError as e:
                log.exception(e)
            except IndexError:
                pass

        executed_fuc = instruction[-1]
        reg_list = instruction[1 : len(instruction) - 1]
        value_of_reg_list = []

        # query the value from hash table based on register index.
        for reg in reg_list:
            index = int(reg[1:])
            obj_stack = self.table_obj.get_obj_list(index)
            if obj_stack:
                var_obj = self.table_obj.pop(index)
                value_of_reg_list.append(var_obj.value)

        # Remove duplicate parameter values to save memory
        seen = {}
        for idx, val in enumerate(value_of_reg_list):
            if val in seen:
                value_of_reg_list[idx] = f"<ref_{seen[val]}>"
            else:
                seen[val] = idx

        invoked_state = f"{executed_fuc}({','.join(value_of_reg_list)})"

        # insert the function and the parameter into called_by_func
        for reg in reg_list:
            index = int(reg[1:])

            if not self.table_obj.get_obj_list(index):
                continue

            # add the function name into each parameter table
            var_obj = self.table_obj.pop(index)
            var_obj.called_by_func = invoked_state

            if var_obj.bears_object():
                # If the register bears an object, update its value to reflect
                # the method invocation since the method may modify the
                # internal state of the object.
                var_obj.value = invoked_state

        if not executed_fuc.endswith(")V"):
            # push the return value into ret_stack
            self.ret_stack.append(invoked_state)

            # Extract the type of return value
            self.ret_type = executed_fuc[executed_fuc.index(")") + 1:]

    def _move_result(self, instruction):

        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = RegisterObject(
                value=pre_ret, value_type=self.ret_type
            )
            self.table_obj.insert(index, variable_object)
            self.ret_type = ""
        except IndexError as e:

            log.exception(f"{e} in _move_result")

    def _move_object(self, src_reg_idx: int, dest_reg_idx: int):
        """
        Move object from src_reg_idx to dest_reg_idx without creating new
        RegisterObject. This allow both registers to point to the same object.
        """
        # Get the source object from the table
        src_obj = self.table_obj.pop(src_reg_idx)

        # Insert the source object to the destination register.
        self.table_obj.insert(dest_reg_idx, src_obj)

    def _assign_value(self, instruction, value_type=""):

        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = RegisterObject(value=value, value_type=value_type)
        self.table_obj.insert(index, variable_object)

    def _assign_value_wide(self, instruction, value_type=""):
        """
        For 64 bit, it has two register, which is vx and vx+1
        """
        reg = instruction[1]
        value = instruction[2]
        index = int(reg[1:])

        variable_object = RegisterObject(value=value, value_type=value_type)
        variable_object2 = RegisterObject(value=value, value_type=value_type)
        self.table_obj.insert(index, variable_object)
        self.table_obj.insert(index + 1, variable_object2)

    @logger
    def INVOKE_VIRTUAL(self, instruction):
        """
        invoke-virtual { parameters }, methodtocall
        invoke-virtual/range { parameters }, methodtocall

        Invokes a virtual method with parameters.
        """
        self._invoke(instruction, look_up=True)

    @logger
    def INVOKE_DIRECT(self, instruction):
        """
        invoke-direct { parameters }, methodtocall
        invoke-direct/range { parameters }, methodtocall

        Invokes a method with parameters without the virtual method resolution. (first parameter is "this")
        """
        self._invoke(instruction)

    @logger
    def INVOKE_STATIC(self, instruction):
        """
        invoke-static {parameters}, methodtocall
        invoke-static/range {parameters}, methodtocall

        Invokes a static method with parameters.
        """
        self._invoke(instruction)

    @logger
    def INVOKE_INTERFACE(self, instruction):
        """
        invoke-interface { parameters }, methodtocall
        invoke-interface/range { parameters }, methodtocall
        
        Invokes a interface method with parameters.
        """
        self._invoke(instruction, look_up=True)

    @logger
    def INVOKE_SUPER(self, instruction):
        """
        invoke-super { parameters }, methodtocall
        invoke-super/range { parameters }, methodtocall
        
        Invokes a super method with parameters.
        """
        self._invoke(instruction, look_up=True, skip_self=True)

    def INVOKE_POLYMORPHIC(self, instruction):
        """
        invoke-polymorphic { parameters }, methodtocall
        invoke-polymorphic/range { parameters }, methodtocall
        
        Invokes a polymorphic method with parameters.
        """
        self._invoke(instruction)

    def INVOKE_CUSTOM(self, instruction):
        """
        invoke-custom { parameters }, callsite
        invoke-custom/range { parameters }, callsite
        
        Invokes a call site with parameters.
        """
        self._invoke(instruction)

    @logger
    def MOVE_RESULT(self, instruction):
        """
        move-result vx

        Move the result value of the previous method invocation into vx.

        Save the value returned by the previous function call to the vx register,and then insert the VariableObject
        into table.
        """
        self._move_result(instruction)

    @logger
    def MOVE_RESULT_WIDE(self, instruction):
        """
        move-result-wide vx

        Move the long/double result value of the previous method invocation into vx,vx+1.
        """
        reg = instruction[1]
        index = int(reg[1:])
        try:
            pre_ret = self.ret_stack.pop()
            variable_object = RegisterObject(value=pre_ret, value_type=self.ret_type)
            variable_object2 = RegisterObject(
                value=pre_ret, value_type=self.ret_type
            )
            self.table_obj.insert(index, variable_object)
            self.table_obj.insert(index + 1, variable_object2)
        except IndexError as e:
            log.exception(f"{e} in MOVE_RESULT_WIDE")

    @logger
    def MOVE_RESULT_OBJECT(self, instruction):
        """
        move-result-object vx

        Move the result object reference of the previous method invocation into vx.

        Save the value returned by the previous function call to the vx register,and then insert the VariableObject
        into table.
        """

        self._move_result(instruction)

    @logger
    def NEW_INSTANCE(self, instruction):
        """
        new-instance vx,type

        Instantiates an object type and puts the reference of the newly created instance into vx.

        Store variables to vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction, value_type=instruction[2])

    @logger
    def NEW_ARRAY(self, instruction):
        try:
            self._move_value_to_register(
                instruction[:-1],
                "new-array()[({src0})",
                value_type=instruction[-1],
            )
        except IndexError as e:
            log.exception(f"{e} in NEW_ARRAY")

    @logger
    def CONST_STRING(self, instruction):
        """
        const-string vx,string_id

        Puts reference to a string constant identified by string_id into vx.

        Store string variable to vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction, value_type="Ljava/lang/String;")

    @logger
    def CONST_CLASS(self, instruction):
        self._assign_value(instruction, value_type="Ljava/lang/Class;")

    @logger
    def CONST(self, instruction):
        """
        const vx, lit32

        Puts the integer constant into vx.
        """
        self._assign_value(instruction)

    @logger
    def CONST_FOUR(self, instruction):
        """
        const/4 vx,lit4

        Puts the 4 bit constant into vx.

        Store 4 bit constant into vx, and then insert the VariableObject into table.
        """

        self._assign_value(instruction)

    @logger
    def CONST_SIXTEEN(self, instruction):
        """
        const/16 vx,lit16

        Puts the 4 bit constant into vx.
        """
        self._assign_value(instruction)

    @logger
    def CONST_HIGHSIXTEEN(self, instruction):
        """
        const/high16 v0, lit16

        Puts the 16 bit constant into the topmost bits of the register. Used to initialize float values.
        """

        self._assign_value(instruction)

    @logger
    def CONST_WIDE(self, instruction):
        """
        const-wide vx, lit64

        Puts the 64 bit constant into vx and vx+1 registers.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_SIXTEEN(self, instruction):
        """
        const-wide/16 vx, lit16

        Puts the integer constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_THIRTY_TWO(self, instruction):
        """
        const-wide/32 vx, lit32

        Puts the 32 bit constant into vx and vx+1 registers, expanding the integer constant into a long constant.
        """
        self._assign_value_wide(instruction)

    @logger
    def CONST_WIDE_HIGHSIXTEEN(self, instruction):
        """
        const-wide/high16 vx,lit16

        Puts the 16 bit constant into the highest 16 bit of vx and vx+1 registers. Used to initialize double values.
        """
        self._assign_value_wide(instruction)

    @logger
    def AGET_KIND(self, instruction):
        """
        aget-kind vx,vy,vz

        Gets an object reference value of an object reference array into vx. The array is referenced by vy and is
        indexed by vz.

        It means vx = vy[vz].
        """

        try:
            if "-" in instruction[0] and "object" not in instruction[0]:
                index = instruction[0].index("-") + 1
                value_type = self.type_mapping[instruction[0][index:]]
            else:
                array_reg_index = int(instruction[2][1:])
                value_type = self.table_obj.pop(array_reg_index).current_type
                # If value_type is not None
                if value_type:
                    value_type = value_type[1:]

            self._move_value_to_register(
                instruction, "{src0}[{src1}]", wide=True, value_type=value_type
            )
        except IndexError as e:
            log.exception(f"{e} in AGET_OBJECT")

    @logger
    def MOVE_KIND(self, instruction):
        try:
            if instruction[0].startswith("move-object"):
                self._move_object(
                    src_reg_idx=int(instruction[2][1:]),
                    dest_reg_idx=int(instruction[1][1:]),
                )
                return

            wide = "wide" in instruction[0]
            self._move_value_to_register(instruction, "{src0}", wide=wide)
        except IndexError as e:
            log.exception(f"{e} in MOVE_KIND")

    @logger
    def FILLED_NEW_ARRAY_KIND(self, instruction):
        value_type = instruction[-1]

        try:
            self._invoke(instruction[:-1] + [f"new-array(){value_type}"])
        except IndexError as e:
            log.exception(f"{e} in MOVE_KIND")

    @logger
    def AGET_WIDE_KIND(self, instruction):
        array_reg_index = int(instruction[2][1:])


        try:
            value_type = self.table_obj.pop(array_reg_index).current_type[1:]
            destination = int(instruction[1][1:])
            source_list = [int(reg[1:]) for reg in instruction[2:]]

            self._transfer_register(
                source_list,
                destination,
                "{src0}[{src1}]",
                value_type=value_type,
            )
            self._transfer_register(
                source_list,
                destination + 1,
                "{src0}[{src1}]",
                value_type=value_type,
            )
        except IndexError as e:
            log.exception(f"{e} in {instruction[0]}")

    @logger
    def APUT_KIND(self, instruction):
        try:
            value, array_reference, index = instruction[1:]
            self._move_value_to_register(
                (None, array_reference, array_reference, index, value),
                "{src0}[{src1}]:{src2}",
            )
        except IndexError as e:
            log.exception(f"{e} in {instruction[0]}")

    @logger
    def APUT_WIDE_KIND(self, instruction):
        try:
            value, array_reference, index = instruction[1:]
            self._move_value_to_register(
                (
                    None,
                    array_reference,
                    array_reference,
                    index,
                    value,
                    f"v{int(value[1:])+1}",
                ),
                "{src0}[{src1}]:({src2}, {src3})",
            )
        except IndexError as e:
            log.exception(f"{e} in {instruction[0]}")

    @logger
    def NEG_AND_NOT_KIND(self, instruction):
        try:
            wide = any(wide_type in instruction[0] for wide_type in ("double", "long"))
            self._move_value_to_register(instruction, "{src0}", wide)
        except IndexError as e:
            log.exception(f"{e} in {instruction[0]}")

    @logger
    def CAST_TYPE(self, instruction):
        try:
            part = instruction[0].split("-")
            value_type = self.type_mapping[part[1]]

            if part[0] in ("double", "long"):
                self._move_value_to_register(
                    instruction + [f"v{int(instruction[2][1:])+1}"],
                    "casting({src0}, {src1})",
                    value_type=value_type,
                )
            elif part[1] in ("double", "long"):
                self._move_value_to_register(
                    instruction,
                    "casting({src0})",
                    value_type=value_type,
                )
                self._move_value_to_register(
                    [
                        instruction[0],
                        f"v{int(instruction[1][1:])+1}",
                        instruction[2],
                    ],
                    "casting({src0})",
                    value_type=value_type,
                )
            else:
                self._move_value_to_register(
                    instruction,
                    "casting({src0})",
                    value_type=value_type,
                )
        except IndexError as e:
            log.exception(f"{e} in {instruction[0]}")

    @logger
    def BINOP_KIND(self, instruction):
        mnemonic = instruction[0]
        index = mnemonic.index("-") + 1
        if "/" in mnemonic:
            r_index = mnemonic.index("/")
            value_type = self.type_mapping[mnemonic[index:r_index]]
        else:
            value_type = self.type_mapping[mnemonic[index:]]

        try:
            wide = value_type in ("D", "J")

            if "/2addr" in instruction[0]:
                self._combine_value_to_register(
                    instruction,
                    "binop({src0}, {src1})",
                    wide,
                    value_type=value_type,
                )
            elif "/lit" in instruction[0]:
                self._move_value_and_data_to_register(
                    instruction,
                    "binop({src0}, {data})",
                    wide,
                    value_type=value_type,
                )
            else:
                self._move_value_to_register(
                    instruction,
                    "binop({src0}, {src1})",
                    wide,
                    value_type=value_type,
                )
        except IndexError as e:
            log.exception(f"{e} in BINOP_KIND")

    def show_table(self):
        return self.table_obj.get_table()

    def _move_value_to_register(
        self, instruction, str_format, wide=False, value_type=None
    ):
        destination = int(instruction[1][1:])
        source_list = [int(reg[1:]) for reg in instruction[2:]]

        self._transfer_register(
            source_list, destination, str_format, value_type=value_type
        )

        if wide:
            pair_source_list = [src + 1 for src in source_list]
            pair_destination = destination + 1
            self._transfer_register(
                pair_source_list,
                pair_destination,
                str_format,
                value_type=value_type,
            )

    def _lookup_implement(self, instance_type, method_full_name, skip_self=False):
        class_name, signature = method_full_name.split("->")
        index = signature.index("(")
        method_name, descriptor = signature[:index], signature[index:]

        class_pool = (
            self.apkinfo.superclass_relationships[instance_type]
            if skip_self
            else {instance_type}
        )
        next_class_pool = set()
        while class_pool and not (
            len(class_pool) == 1 and "Ljava/lang/Object;" in class_pool
        ):
            next_class_pool.clear()
            for class_name in class_pool:
                method_list = self.apkinfo.find_method(
                    class_name, method_name, descriptor
                )

                if method_list:
                    return PyEval.get_method_pattern(
                        method_list[0].class_name,
                        method_list[0].name,
                        method_list[0].descriptor,
                    )

                next_class_pool.update(
                    (self.apkinfo.superclass_relationships[class_name])
                )
                next_class_pool.difference_update(class_pool)

            class_pool = set(next_class_pool)

        raise ValueError(
            "The implement of method {signature} was"
            "not found. Instance type: {instance_type}"
        )

    def _move_value_and_data_to_register(
        self, instruction, str_format, wide=False, value_type=None
    ):
        destination = int(instruction[1][1:])
        source_list = [int(reg[1:]) for reg in instruction[2:-1]]
        data = instruction[-1]

        for source in source_list:
            if not self.table_obj.get_obj_list(source):
                value_dict = {
                    f"src{0}": instruction
                }
                value_dict["data"] = data

                new_register = RegisterObject(
                    value=str_format.format(**value_dict),
                    value_type=value_type,
                )
                self.table_obj.insert(source, new_register)

        self._transfer_register(
            source_list,
            destination,
            str_format,
            data=data,
            value_type=value_type,
        )

        if wide:
            self._transfer_register(
                source_list,
                destination + 1,
                str_format,
                data=data,
                value_type=value_type,
            )

    def _combine_value_to_register(
        self, instruction, str_format, wide=False, value_type=""
    ):
        self._move_value_to_register(
            instruction[0:2] + instruction[1:],
            str_format,
            wide,
            value_type=value_type,
        )

    def _transfer_register(
        self, source_list, destination, str_format, data=None, value_type=None
    ):
        try:
            source_register_list = [self.table_obj.pop(index) for index in source_list]
        except IndexError:
            return

        if not value_type:
            value_type = source_register_list[0].current_type

        value_dict = {
            f"src{index}": register.value
            for index, register in enumerate(source_register_list)
        }
        value_dict["data"] = data

        new_register = RegisterObject(
            value=str_format.format(**value_dict),
            value_type=value_type,
        )

        self.table_obj.insert(destination, new_register)

    @staticmethod
    def get_method_pattern(
        class_name: str, method_name: str, descriptor: str
    ) -> str:
        """Convert a method into a string representation to record method calls
         during the tainted analysis.

        :param class_name: the class name of the method
        :param method_name: the name of the method
        :param descriptor: the descriptor of the method
        :return: a string representation of the method
        """
        return f"{class_name}->{method_name}{descriptor}"


if __name__ == "__main__":
    pass

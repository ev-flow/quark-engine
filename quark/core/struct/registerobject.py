# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.


class RegisterObject:
    """The RegisterObject is used to record the state of each register"""

    __slots__ = [
        "_value",
        "_called_by_func",
        "_current_type",
        "_type_history",
    ]

    def __init__(self, value, called_by_func=None, value_type=None):
        """
        A data structure for creating the bytecode variable object, which
        used to record the state of each register.

        +========+==================+
        | value | called_by_func    |
        +========+==================+

        :param value:
        :param called_by_func:
        """
        self._value = value
        self._current_type = value_type
        self._type_history = []
        self._called_by_func = []
        if called_by_func is not None:
            self._called_by_func.append(called_by_func)

    def __repr__(self):
        return f"<VarabileObject-value:{self._value}, called_by_func:{','.join(self._called_by_func)}, current_type:{self._current_type}>"

    def __eq__(self, obj):
        return (
            isinstance(obj, RegisterObject)
            and obj.called_by_func == self.called_by_func
            and obj.value == self.value
            and obj.current_type == self.current_type
        )

    @property
    def called_by_func(self):
        """
        Record which functions have been called by using this register as a parameter.

        :return: a list containing function name
        """
        return self._called_by_func

    @called_by_func.setter
    def called_by_func(self, called_by_func):
        """
        Setter of called_by_func.

        :param called_by_func:
        :return: None
        """
        self._called_by_func.append(called_by_func)
        self._type_history.append(self._current_type)

    @property
    def value(self):
        """
        The current value stored in the register.

        :return: a string of the value
        """
        return self._value

    @value.setter
    def value(self, value):
        """
        Setter of value.

        :param value:
        :return: None
        """
        self._value = value

    @property
    def current_type(self):
        """
        Get the type of the value in the register

        :return: a plant text that describes a data type
        :rtype: str
        """
        return self._current_type

    @current_type.setter
    def current_type(self, value):
        self._current_type = value

    @property
    def type_histroy(self):
        return self._type_history

    def bears_object(self) -> bool:
        """
        Check whether the register bears an object.

        :return: True if the register bears an object, False otherwise
        :rtype: bool
        """
        return self.current_type is not None and self.current_type.startswith("L")

if __name__ == "__main__":
    pass

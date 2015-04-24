LOCAL_PATH			:= $(call my-dir)
include $(CLEAR_VARS)

SRC_ROOT			:= ..

LOCAL_MODULE		:= Aprof
LOCAL_SRC_FILES		:=	$(SRC_ROOT)/Aprof.cpp
LOCAL_LDFLAGS       += -llog

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

SRC_ROOT			:= ..

LOCAL_MODULE		:= AprofTest_mm
LOCAL_SRC_FILES		:=	$(SRC_ROOT)/AprofTest_mm.cpp

include $(BUILD_SHARED_LIBRARY)


include $(CLEAR_VARS)

SRC_ROOT			:= ..

LOCAL_MODULE		:= AprofTest
LOCAL_SRC_FILES		:=	$(SRC_ROOT)/AprofTest.cpp
LOCAL_SHARED_LIBRARIES := Aprof AprofTest_mm

include $(BUILD_EXECUTABLE)
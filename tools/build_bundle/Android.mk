LOCAL_PATH := $(call my-dir)

#################################
include $(CLEAR_VARS)

LOCAL_MODULE := buildbundle
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	$(call all-java-files-under, src) \
	../../../../frameworks/base/core/java/android/util/Base64.java

LOCAL_JAR_MANIFEST := BuildBundle.mf

LOCAL_STATIC_JAVA_LIBRARIES := guavalib

include $(BUILD_HOST_JAVA_LIBRARY)

##################################
include $(CLEAR_VARS)

LOCAL_MODULE_TAGS := optional

LOCAL_PREBUILT_EXECUTABLES := buildbundle

include $(BUILD_HOST_PREBUILT)

##################################
include $(CLEAR_VARS)

LOCAL_REQUIRED_MODULES := buildbundle
LOCAL_MODULE := buildsebundle
LOCAL_SRC_FILES := buildsebundle
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE_TAGS := optional

include $(BUILD_PREBUILT)

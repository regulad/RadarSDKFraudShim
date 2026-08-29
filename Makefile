TARGET := iphone:clang:latest:15.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = roothide

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = RadarSDKFraudShim
RadarSDKFraudShim_FILES = Tweak.x
RadarSDKFraudShim_CFLAGS = -fobjc-arc
RadarSDKFraudShim_FRAMEWORKS = Foundation

ifneq ($(FINALPACKAGE),1)
RadarSDKFraudShim_CFLAGS += -DRADAR_DIAG=1
endif

include $(THEOS_MAKE_PATH)/tweak.mk

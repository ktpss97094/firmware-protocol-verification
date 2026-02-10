#define EIDSP_SIGNAL_C_FN_POINTER 1
#define EI_C_LINKAGE 1

#include "function.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "edge-impulse-sdk/classifier/ei_classifier_types.h"
#include "edge-impulse-sdk/dsp/numpy_types.h"
#include "edge-impulse-sdk/porting/ei_classifier_porting.h"

int get_feature_data(size_t offset, size_t length, float *out_ptr);
int read_features_file(const char *filename);
int Lungclassification(int argc, char **argv);
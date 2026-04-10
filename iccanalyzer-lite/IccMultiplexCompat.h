// IccMultiplexCompat.h -- Compatibility macros for the upstream
// Material* -> Multiplex* rename (iccDEV master, April 2025).
// Include after icProfileHeader.h / IccProfile.h.
#ifndef ICC_MULTIPLEX_COMPAT_H
#define ICC_MULTIPLEX_COMPAT_H

// Class signatures
#ifndef icSigMultiplexIdentificationClass
  #ifdef icSigMaterialIdentificationClass
    #define icSigMultiplexIdentificationClass icSigMaterialIdentificationClass
  #endif
#endif
#ifndef icSigMultiplexLinkClass
  #ifdef icSigMaterialLinkClass
    #define icSigMultiplexLinkClass icSigMaterialLinkClass
  #endif
#endif
#ifndef icSigMultiplexVisualizationClass
  #ifdef icSigMaterialVisualizationClass
    #define icSigMultiplexVisualizationClass icSigMaterialVisualizationClass
  #endif
#endif

// Tag signatures
#ifndef icSigMultiplexDefaultValuesTag
  #ifdef icSigMaterialDefaultValuesTag
    #define icSigMultiplexDefaultValuesTag icSigMaterialDefaultValuesTag
  #else
    #define icSigMultiplexDefaultValuesTag static_cast<icTagSignature>(0x6D647620)
  #endif
#endif
#ifndef icSigMultiplexTypeArrayTag
  #ifdef icSigMaterialTypeArrayTag
    #define icSigMultiplexTypeArrayTag icSigMaterialTypeArrayTag
  #else
    #define icSigMultiplexTypeArrayTag static_cast<icTagSignature>(0x6d637461)
  #endif
#endif

// Typedef
#if !defined(icMultiplexColorSignature) && defined(icMaterialColorSignature)
  typedef icMaterialColorSignature icMultiplexColorSignature;
#endif

// Function
#if !defined(icGetMultiplexColorSpaceSamples)
  #if defined(icGetMaterialColorSpaceSamples)
    #define icGetMultiplexColorSpaceSamples icGetMaterialColorSpaceSamples
  #endif
#endif

#endif // ICC_MULTIPLEX_COMPAT_H

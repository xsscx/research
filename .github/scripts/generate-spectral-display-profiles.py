#!/usr/bin/env python3
"""Generate ICC v5 display profiles with spectral emission AToB1 tags.

Creates 6 profiles with different spectral emission characteristics (Gaussian
primaries), compiles them via iccFromXml, and verifies with iccV5DspObsToV4Dsp.
XML structure matches iccDEV Rec2020rgbSpectral.xml exactly.
"""

import argparse
import math
import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# CIE 1931 2-degree observer (380-780nm, 1nm steps, 401 values)
# ---------------------------------------------------------------------------
XBAR = [
    0.001368, 0.001542, 0.001715, 0.001889, 0.002062, 0.002236, 0.002637,
    0.003039, 0.003440, 0.003842, 0.004243, 0.004924, 0.005606, 0.006287,
    0.006969, 0.007650, 0.008982, 0.010314, 0.011646, 0.012978, 0.014310,
    0.016086, 0.017862, 0.019638, 0.021414, 0.023190, 0.027254, 0.031318,
    0.035382, 0.039446, 0.043510, 0.050334, 0.057158, 0.063982, 0.070806,
    0.077630, 0.088980, 0.100330, 0.111680, 0.123030, 0.134380, 0.150458,
    0.166536, 0.182614, 0.198692, 0.214770, 0.228596, 0.242422, 0.256248,
    0.270074, 0.283900, 0.292820, 0.301740, 0.310660, 0.319580, 0.328500,
    0.332456, 0.336412, 0.340368, 0.344324, 0.348280, 0.348236, 0.348192,
    0.348148, 0.348104, 0.348060, 0.345688, 0.343316, 0.340944, 0.338572,
    0.336200, 0.332700, 0.329200, 0.325700, 0.322200, 0.318700, 0.313120,
    0.307540, 0.301960, 0.296380, 0.290800, 0.282860, 0.274920, 0.266980,
    0.259040, 0.251100, 0.239952, 0.228804, 0.217656, 0.206508, 0.195360,
    0.184708, 0.174056, 0.163404, 0.152752, 0.142100, 0.132808, 0.123516,
    0.114224, 0.104932, 0.095640, 0.088102, 0.080564, 0.073026, 0.065488,
    0.057950, 0.052762, 0.047574, 0.042386, 0.037198, 0.032010, 0.028548,
    0.025086, 0.021624, 0.018162, 0.014700, 0.012740, 0.010780, 0.008820,
    0.006860, 0.004900, 0.004400, 0.003900, 0.003400, 0.002900, 0.002400,
    0.003780, 0.005160, 0.006540, 0.007920, 0.009300, 0.013260, 0.017220,
    0.021180, 0.025140, 0.029100, 0.035934, 0.042768, 0.049602, 0.056436,
    0.063270, 0.072536, 0.081802, 0.091068, 0.100334, 0.109600, 0.120780,
    0.131960, 0.143140, 0.154320, 0.165500, 0.177550, 0.189600, 0.201650,
    0.213700, 0.225750, 0.238680, 0.251610, 0.264540, 0.277470, 0.290400,
    0.304260, 0.318120, 0.331980, 0.345840, 0.359700, 0.374450, 0.389200,
    0.403950, 0.418700, 0.433450, 0.449170, 0.464890, 0.480610, 0.496330,
    0.512050, 0.528540, 0.545030, 0.561520, 0.578010, 0.594500, 0.611280,
    0.628060, 0.644840, 0.661620, 0.678400, 0.695140, 0.711880, 0.728620,
    0.745360, 0.762100, 0.778180, 0.794260, 0.810340, 0.826420, 0.842500,
    0.857260, 0.872020, 0.886780, 0.901540, 0.916300, 0.928760, 0.941220,
    0.953680, 0.966140, 0.978600, 0.988140, 0.997680, 1.007220, 1.016760,
    1.026300, 1.032380, 1.038460, 1.044540, 1.050620, 1.056700, 1.057800,
    1.058900, 1.060000, 1.061100, 1.062200, 1.058880, 1.055560, 1.052240,
    1.048920, 1.045600, 1.037000, 1.028400, 1.019800, 1.011200, 1.002600,
    0.989760, 0.976920, 0.964080, 0.951240, 0.938400, 0.921610, 0.904820,
    0.888030, 0.871240, 0.854450, 0.833840, 0.813230, 0.792620, 0.772010,
    0.751400, 0.729600, 0.707800, 0.686000, 0.664200, 0.642400, 0.622300,
    0.602200, 0.582100, 0.562000, 0.541900, 0.523100, 0.504300, 0.485500,
    0.466700, 0.447900, 0.430480, 0.413060, 0.395640, 0.378220, 0.360800,
    0.345340, 0.329880, 0.314420, 0.298960, 0.283500, 0.270540, 0.257580,
    0.244620, 0.231660, 0.218700, 0.207940, 0.197180, 0.186420, 0.175660,
    0.164900, 0.156160, 0.147420, 0.138680, 0.129940, 0.121200, 0.114440,
    0.107680, 0.100920, 0.094160, 0.087400, 0.082640, 0.077880, 0.073120,
    0.068360, 0.063600, 0.060234, 0.056868, 0.053502, 0.050136, 0.046770,
    0.043996, 0.041222, 0.038448, 0.035674, 0.032900, 0.030860, 0.028820,
    0.026780, 0.024740, 0.022700, 0.021328, 0.019956, 0.018584, 0.017212,
    0.015840, 0.014944, 0.014048, 0.013151, 0.012255, 0.011359, 0.010709,
    0.010060, 0.009410, 0.008761, 0.008111, 0.007647, 0.007183, 0.006718,
    0.006254, 0.005790, 0.005454, 0.005118, 0.004781, 0.004445, 0.004109,
    0.003867, 0.003625, 0.003383, 0.003141, 0.002899, 0.002729, 0.002559,
    0.002389, 0.002219, 0.002049, 0.001927, 0.001805, 0.001684, 0.001562,
    0.001440, 0.001352, 0.001264, 0.001176, 0.001088, 0.001000, 0.000938,
    0.000876, 0.000814, 0.000752, 0.000690, 0.000647, 0.000604, 0.000562,
    0.000519, 0.000476, 0.000447, 0.000418, 0.000390, 0.000361, 0.000332,
    0.000313, 0.000293, 0.000274, 0.000254, 0.000235, 0.000221, 0.000207,
    0.000194, 0.000180, 0.000166, 0.000156, 0.000146, 0.000137, 0.000127,
    0.000117, 0.000110, 0.000103, 0.000097, 0.000090, 0.000083, 0.000078,
    0.000073, 0.000069, 0.000064, 0.000059, 0.000056, 0.000052, 0.000049,
    0.000045, 0.000042,
]

YBAR = [
    0.000039, 0.000044, 0.000049, 0.000054, 0.000059, 0.000064, 0.000075,
    0.000086, 0.000098, 0.000109, 0.000120, 0.000139, 0.000159, 0.000178,
    0.000198, 0.000217, 0.000253, 0.000289, 0.000324, 0.000360, 0.000396,
    0.000445, 0.000494, 0.000542, 0.000591, 0.000640, 0.000754, 0.000868,
    0.000982, 0.001096, 0.001210, 0.001404, 0.001598, 0.001792, 0.001986,
    0.002180, 0.002544, 0.002908, 0.003272, 0.003636, 0.004000, 0.004660,
    0.005320, 0.005980, 0.006640, 0.007300, 0.008160, 0.009020, 0.009880,
    0.010740, 0.011600, 0.012648, 0.013696, 0.014744, 0.015792, 0.016840,
    0.018072, 0.019304, 0.020536, 0.021768, 0.023000, 0.024360, 0.025720,
    0.027080, 0.028440, 0.029800, 0.031440, 0.033080, 0.034720, 0.036360,
    0.038000, 0.040000, 0.042000, 0.044000, 0.046000, 0.048000, 0.050400,
    0.052800, 0.055200, 0.057600, 0.060000, 0.062780, 0.065560, 0.068340,
    0.071120, 0.073900, 0.077316, 0.080732, 0.084148, 0.087564, 0.090980,
    0.095304, 0.099628, 0.103952, 0.108276, 0.112600, 0.117884, 0.123168,
    0.128452, 0.133736, 0.139020, 0.145076, 0.151132, 0.157188, 0.163244,
    0.169300, 0.177044, 0.184788, 0.192532, 0.200276, 0.208020, 0.218136,
    0.228252, 0.238368, 0.248484, 0.258600, 0.271480, 0.284360, 0.297240,
    0.310120, 0.323000, 0.339860, 0.356720, 0.373580, 0.390440, 0.407300,
    0.426440, 0.445580, 0.464720, 0.483860, 0.503000, 0.524040, 0.545080,
    0.566120, 0.587160, 0.608200, 0.628560, 0.648920, 0.669280, 0.689640,
    0.710000, 0.726640, 0.743280, 0.759920, 0.776560, 0.793200, 0.806960,
    0.820720, 0.834480, 0.848240, 0.862000, 0.872570, 0.883140, 0.893710,
    0.904280, 0.914850, 0.922680, 0.930510, 0.938340, 0.946170, 0.954000,
    0.959260, 0.964520, 0.969780, 0.975040, 0.980300, 0.983230, 0.986160,
    0.989090, 0.992020, 0.994950, 0.995960, 0.996970, 0.997980, 0.998990,
    1.000000, 0.999000, 0.998000, 0.997000, 0.996000, 0.995000, 0.991720,
    0.988440, 0.985160, 0.981880, 0.978600, 0.973280, 0.967960, 0.962640,
    0.957320, 0.952000, 0.944680, 0.937360, 0.930040, 0.922720, 0.915400,
    0.906320, 0.897240, 0.888160, 0.879080, 0.870000, 0.859260, 0.848520,
    0.837780, 0.827040, 0.816300, 0.804440, 0.792580, 0.780720, 0.768860,
    0.757000, 0.744580, 0.732160, 0.719740, 0.707320, 0.694900, 0.682120,
    0.669340, 0.656560, 0.643780, 0.631000, 0.618160, 0.605320, 0.592480,
    0.579640, 0.566800, 0.554040, 0.541280, 0.528520, 0.515760, 0.503000,
    0.490640, 0.478280, 0.465920, 0.453560, 0.441200, 0.429160, 0.417120,
    0.405080, 0.393040, 0.381000, 0.369000, 0.357000, 0.345000, 0.333000,
    0.321000, 0.309800, 0.298600, 0.287400, 0.276200, 0.265000, 0.255400,
    0.245800, 0.236200, 0.226600, 0.217000, 0.208600, 0.200200, 0.191800,
    0.183400, 0.175000, 0.167640, 0.160280, 0.152920, 0.145560, 0.138200,
    0.131960, 0.125720, 0.119480, 0.113240, 0.107000, 0.101920, 0.096840,
    0.091760, 0.086680, 0.081600, 0.077480, 0.073360, 0.069240, 0.065120,
    0.061000, 0.057716, 0.054432, 0.051148, 0.047864, 0.044580, 0.042064,
    0.039548, 0.037032, 0.034516, 0.032000, 0.030240, 0.028480, 0.026720,
    0.024960, 0.023200, 0.021960, 0.020720, 0.019480, 0.018240, 0.017000,
    0.015984, 0.014968, 0.013952, 0.012936, 0.011920, 0.011178, 0.010436,
    0.009694, 0.008952, 0.008210, 0.007713, 0.007215, 0.006718, 0.006220,
    0.005723, 0.005399, 0.005075, 0.004750, 0.004426, 0.004102, 0.003867,
    0.003633, 0.003398, 0.003164, 0.002929, 0.002761, 0.002594, 0.002426,
    0.002259, 0.002091, 0.001970, 0.001848, 0.001727, 0.001605, 0.001484,
    0.001397, 0.001309, 0.001222, 0.001134, 0.001047, 0.000986, 0.000924,
    0.000863, 0.000801, 0.000740, 0.000696, 0.000652, 0.000608, 0.000564,
    0.000520, 0.000488, 0.000456, 0.000425, 0.000393, 0.000361, 0.000339,
    0.000316, 0.000294, 0.000271, 0.000249, 0.000234, 0.000218, 0.000203,
    0.000187, 0.000172, 0.000162, 0.000151, 0.000141, 0.000130, 0.000120,
    0.000113, 0.000106, 0.000099, 0.000092, 0.000085, 0.000080, 0.000075,
    0.000070, 0.000065, 0.000060, 0.000056, 0.000053, 0.000049, 0.000046,
    0.000042, 0.000040, 0.000037, 0.000035, 0.000032, 0.000030, 0.000028,
    0.000026, 0.000025, 0.000023, 0.000021, 0.000020, 0.000019, 0.000017,
    0.000016, 0.000015,
]

ZBAR = [
    0.006450, 0.007270, 0.008090, 0.008910, 0.009730, 0.010550, 0.012450,
    0.014350, 0.016250, 0.018150, 0.020050, 0.023282, 0.026514, 0.029746,
    0.032978, 0.036210, 0.042538, 0.048866, 0.055194, 0.061522, 0.067850,
    0.076320, 0.084790, 0.093260, 0.101730, 0.110200, 0.129640, 0.149080,
    0.168520, 0.187960, 0.207400, 0.240180, 0.272960, 0.305740, 0.338520,
    0.371300, 0.426160, 0.481020, 0.535880, 0.590740, 0.645600, 0.724290,
    0.802980, 0.881670, 0.960360, 1.039050, 1.108360, 1.177670, 1.246980,
    1.316290, 1.385600, 1.433072, 1.480544, 1.528016, 1.575488, 1.622960,
    1.647780, 1.672600, 1.697420, 1.722240, 1.747060, 1.754168, 1.761276,
    1.768384, 1.775492, 1.782600, 1.780502, 1.778404, 1.776306, 1.774208,
    1.772110, 1.766508, 1.760906, 1.755304, 1.749702, 1.744100, 1.729120,
    1.714140, 1.699160, 1.684180, 1.669200, 1.640980, 1.612760, 1.584540,
    1.556320, 1.528100, 1.480008, 1.431916, 1.383824, 1.335732, 1.287640,
    1.238492, 1.189344, 1.140196, 1.091048, 1.041900, 0.996110, 0.950320,
    0.904530, 0.858740, 0.812950, 0.773600, 0.734250, 0.694900, 0.655550,
    0.616200, 0.585996, 0.555792, 0.525588, 0.495384, 0.465180, 0.442804,
    0.420428, 0.398052, 0.375676, 0.353300, 0.337040, 0.320780, 0.304520,
    0.288260, 0.272000, 0.260060, 0.248120, 0.236180, 0.224240, 0.212300,
    0.201480, 0.190660, 0.179840, 0.169020, 0.158200, 0.148900, 0.139600,
    0.130300, 0.121000, 0.111700, 0.105010, 0.098320, 0.091630, 0.084940,
    0.078250, 0.074050, 0.069850, 0.065650, 0.061450, 0.057250, 0.054232,
    0.051214, 0.048196, 0.045178, 0.042160, 0.039696, 0.037232, 0.034768,
    0.032304, 0.029840, 0.027932, 0.026024, 0.024116, 0.022208, 0.020300,
    0.018920, 0.017540, 0.016160, 0.014780, 0.013400, 0.012470, 0.011540,
    0.010610, 0.009680, 0.008750, 0.008150, 0.007550, 0.006950, 0.006350,
    0.005750, 0.005380, 0.005010, 0.004640, 0.004270, 0.003900, 0.003670,
    0.003440, 0.003210, 0.002980, 0.002750, 0.002620, 0.002490, 0.002360,
    0.002230, 0.002100, 0.002040, 0.001980, 0.001920, 0.001860, 0.001800,
    0.001770, 0.001740, 0.001710, 0.001680, 0.001650, 0.001600, 0.001550,
    0.001500, 0.001450, 0.001400, 0.001340, 0.001280, 0.001220, 0.001160,
    0.001100, 0.001080, 0.001060, 0.001040, 0.001020, 0.001000, 0.000960,
    0.000920, 0.000880, 0.000840, 0.000800, 0.000760, 0.000720, 0.000680,
    0.000640, 0.000600, 0.000548, 0.000496, 0.000444, 0.000392, 0.000340,
    0.000320, 0.000300, 0.000280, 0.000260, 0.000240, 0.000230, 0.000220,
    0.000210, 0.000200, 0.000190, 0.000172, 0.000154, 0.000136, 0.000118,
    0.000100, 0.000090, 0.000080, 0.000070, 0.000060, 0.000050, 0.000046,
    0.000042, 0.000038, 0.000034, 0.000030, 0.000028, 0.000026, 0.000024,
    0.000022, 0.000020, 0.000018, 0.000016, 0.000014, 0.000012, 0.000010,
    0.000008, 0.000006, 0.000004, 0.000002, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000,
    0.000000, 0.000000,
]

# D65 illuminant SPD (380-780nm, 1nm steps, 401 values)
D65_SPD = [
    49.975500, 50.442760, 50.910020, 51.377280, 51.844540, 52.311800,
    52.779080, 53.246360, 53.713640, 54.180920, 54.648200, 57.458860,
    60.269520, 63.080180, 65.890840, 68.701500, 71.512180, 74.322860,
    77.133540, 79.944220, 82.754900, 83.628000, 84.501100, 85.374200,
    86.247300, 87.120400, 87.993520, 88.866640, 89.739760, 90.612880,
    91.486000, 91.680580, 91.875160, 92.069740, 92.264320, 92.458900,
    92.653480, 92.848060, 93.042640, 93.237220, 93.431800, 92.756840,
    92.081880, 91.406920, 90.731960, 90.057000, 89.382060, 88.707120,
    88.032180, 87.357240, 86.682300, 88.500560, 90.318820, 92.137080,
    93.955340, 95.773600, 97.591880, 99.410160, 101.228440, 103.046720,
    104.865000, 106.079200, 107.293400, 108.507600, 109.721800, 110.936000,
    112.150400, 113.364800, 114.579200, 115.793600, 117.008000, 117.088400,
    117.168800, 117.249200, 117.329600, 117.410000, 117.490400, 117.570800,
    117.651200, 117.731600, 117.812000, 117.516800, 117.221600, 116.926400,
    116.631200, 116.336000, 116.041000, 115.746000, 115.451000, 115.156000,
    114.861000, 114.967200, 115.073400, 115.179600, 115.285800, 115.392000,
    115.498200, 115.604400, 115.710600, 115.816800, 115.923000, 115.211800,
    114.500600, 113.789400, 113.078200, 112.367000, 111.655800, 110.944600,
    110.233400, 109.522200, 108.811000, 108.865200, 108.919400, 108.973600,
    109.027800, 109.082000, 109.136400, 109.190800, 109.245200, 109.299600,
    109.354000, 109.198800, 109.043600, 108.888400, 108.733200, 108.578000,
    108.422800, 108.267600, 108.112400, 107.957200, 107.802000, 107.500800,
    107.199600, 106.898400, 106.597200, 106.296000, 105.994800, 105.693600,
    105.392400, 105.091200, 104.790000, 105.079800, 105.369600, 105.659400,
    105.949200, 106.239000, 106.529000, 106.819000, 107.109000, 107.399000,
    107.689000, 107.360600, 107.032200, 106.703800, 106.375400, 106.047000,
    105.718600, 105.390200, 105.061800, 104.733400, 104.405000, 104.369000,
    104.333000, 104.297000, 104.261000, 104.225000, 104.189200, 104.153400,
    104.117600, 104.081800, 104.046000, 103.641400, 103.236800, 102.832200,
    102.427600, 102.023000, 101.618400, 101.213800, 100.809200, 100.404600,
    100.000000, 99.633420, 99.266840, 98.900260, 98.533680, 98.167100,
    97.800520, 97.433940, 97.067360, 96.700780, 96.334200, 96.279580,
    96.224960, 96.170340, 96.115720, 96.061100, 96.006480, 95.951860,
    95.897240, 95.842620, 95.788000, 95.077760, 94.367520, 93.657280,
    92.947040, 92.236800, 91.526560, 90.816320, 90.106080, 89.395840,
    88.685600, 88.817660, 88.949720, 89.081780, 89.213840, 89.345900,
    89.477960, 89.610020, 89.742080, 89.874140, 90.006200, 89.965480,
    89.924760, 89.884040, 89.843320, 89.802600, 89.761900, 89.721200,
    89.680500, 89.639800, 89.599100, 89.409060, 89.219020, 89.028980,
    88.838940, 88.648900, 88.458860, 88.268820, 88.078780, 87.888740,
    87.698700, 87.257680, 86.816660, 86.375640, 85.934620, 85.493600,
    85.052600, 84.611600, 84.170600, 83.729600, 83.288600, 83.329660,
    83.370720, 83.411780, 83.452840, 83.493900, 83.534960, 83.576020,
    83.617080, 83.658140, 83.699200, 83.331960, 82.964720, 82.597480,
    82.230240, 81.863000, 81.495760, 81.128520, 80.761280, 80.394040,
    80.026800, 80.045580, 80.064360, 80.083140, 80.101920, 80.120700,
    80.139480, 80.158260, 80.177040, 80.195820, 80.214600, 80.420920,
    80.627240, 80.833560, 81.039880, 81.246200, 81.452520, 81.658840,
    81.865160, 82.071480, 82.277800, 81.878440, 81.479080, 81.079720,
    80.680360, 80.281000, 79.881640, 79.482280, 79.082920, 78.683560,
    78.284200, 77.427900, 76.571600, 75.715300, 74.859000, 74.002700,
    73.146420, 72.290140, 71.433860, 70.577580, 69.721300, 69.910080,
    70.098860, 70.287640, 70.476420, 70.665200, 70.853980, 71.042760,
    71.231540, 71.420320, 71.609100, 71.883080, 72.157060, 72.431040,
    72.705020, 72.979000, 73.253000, 73.527000, 73.801000, 74.075000,
    74.349000, 73.074500, 71.800000, 70.525500, 69.251000, 67.976500,
    66.702000, 65.427500, 64.153000, 62.878500, 61.604000, 62.432160,
    63.260320, 64.088480, 64.916640, 65.744800, 66.572960, 67.401120,
    68.229280, 69.057440, 69.885600, 70.405740, 70.925880, 71.446020,
    71.966160, 72.486300, 73.006440, 73.526580, 74.046720, 74.566860,
    75.087000, 73.937560, 72.788120, 71.638680, 70.489240, 69.339800,
    68.190380, 67.040960, 65.891540, 64.742120, 63.592700, 61.875240,
    60.157780, 58.440320, 56.722860, 55.005400, 53.287960, 51.570520,
    49.853080, 48.135640, 46.418200, 48.456920, 50.495640, 52.534360,
    54.573080, 56.611800, 58.650520, 60.689240, 62.727960, 64.766680,
    66.805400, 66.463140, 66.120880, 65.778620, 65.436360, 65.094100,
    64.751840, 64.409580, 64.067320, 63.725060, 63.382800,
]

WAVELENGTHS = list(range(380, 781))  # 380..780 inclusive = 401 values


# ---------------------------------------------------------------------------
# Spectral emission helpers
# ---------------------------------------------------------------------------

def gaussian(wavelength: float, peak: float, fwhm: float) -> float:
    sigma = fwhm / 2.3548200450309493  # 2*sqrt(2*ln2)
    return math.exp(-0.5 * ((wavelength - peak) / sigma) ** 2)


def make_spectrum(peaks: list[tuple[float, float, float]]) -> list[float]:
    """Generate a normalised spectrum from [(peak_nm, fwhm_nm, weight), ...]."""
    raw = []
    for wl in WAVELENGTHS:
        val = 0.0
        for peak, fwhm, weight in peaks:
            val += weight * gaussian(wl, peak, fwhm)
        raw.append(val)
    mx = max(raw) or 1.0
    return [v / mx for v in raw]


# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

PROFILES = [
    {
        "name": "RGBWProjectorSpectral",
        "desc": "RGBW Projector Spectral Emission (Rec709-like gamma)",
        "r_peaks": [(620, 40, 1.0)],
        "g_peaks": [(540, 35, 1.0)],
        "b_peaks": [(455, 30, 1.0)],
        # Rec709/Rec2020-like transfer (from template)
        "fwd_threshold": "0.0812428582986315",
        "fwd_linear": "1.0 0.222222222222222 0.0 0.0",
        "fwd_gamma": "2.22222222222222 1.0 0.909672415686275 0.0903275843137250 0.0",
        "inv_threshold": "0.018053968510807",
        "inv_linear": "1.0 4.5 0.00000000 0.00000000",
        "inv_gamma": "0.45 1.09929682680944 1.0 0.0 -0.0992968268094401",
    },
    {
        "name": "OLEDDisplaySpectral",
        "desc": "OLED Display Spectral Emission (BT.1886 gamma 2.4)",
        "r_peaks": [(615, 50, 1.0)],
        "g_peaks": [(530, 40, 1.0)],
        "b_peaks": [(465, 30, 1.0)],
        "fwd_threshold": "0.0",
        "fwd_linear": "1.0 1.0 0.0 0.0",
        "fwd_gamma": "2.4 1.0 1.0 0.0 0.0",
        "inv_threshold": "0.0",
        "inv_linear": "1.0 1.0 0.00000000 0.00000000",
        "inv_gamma": "0.416666666666667 1.0 1.0 0.0 0.0",
    },
    {
        "name": "P3DisplaySpectral",
        "desc": "DCI-P3 Display Spectral Emission (gamma 2.6)",
        "r_peaks": [(630, 20, 1.0)],
        "g_peaks": [(530, 25, 1.0)],
        "b_peaks": [(450, 22, 1.0)],
        "fwd_threshold": "0.0",
        "fwd_linear": "1.0 1.0 0.0 0.0",
        "fwd_gamma": "2.6 1.0 1.0 0.0 0.0",
        "inv_threshold": "0.0",
        "inv_linear": "1.0 1.0 0.00000000 0.00000000",
        "inv_gamma": "0.384615384615385 1.0 1.0 0.0 0.0",
    },
    {
        "name": "MicroLEDSpectral",
        "desc": "MicroLED Display Spectral Emission (narrow primaries, gamma 2.2)",
        "r_peaks": [(632, 8, 1.0)],
        "g_peaks": [(525, 10, 1.0)],
        "b_peaks": [(460, 12, 1.0)],
        "fwd_threshold": "0.0",
        "fwd_linear": "1.0 1.0 0.0 0.0",
        "fwd_gamma": "2.2 1.0 1.0 0.0 0.0",
        "inv_threshold": "0.0",
        "inv_linear": "1.0 1.0 0.00000000 0.00000000",
        "inv_gamma": "0.454545454545455 1.0 1.0 0.0 0.0",
    },
    {
        "name": "sRGBDisplaySpectral",
        "desc": "sRGB Display Spectral Emission (sRGB transfer, secondary green peak)",
        "r_peaks": [(610, 60, 1.0)],
        "g_peaks": [(545, 50, 1.0), (490, 20, 0.3)],
        "b_peaks": [(450, 25, 1.0)],
        "fwd_threshold": "0.04045",
        "fwd_linear": "1.0 0.077399380804954 0.0 0.0",
        "fwd_gamma": "2.4 1.0 0.947867298578199 0.052132701421801 0.0",
        "inv_threshold": "0.0031308",
        "inv_linear": "1.0 12.92 0.00000000 0.00000000",
        "inv_gamma": "0.416666666666667 1.055 1.0 0.0 -0.055",
    },
    {
        "name": "WideGamutSpectral",
        "desc": "Wide Gamut Display Spectral Emission (narrow primaries, gamma 2.2)",
        "r_peaks": [(625, 15, 1.0)],
        "g_peaks": [(525, 20, 1.0)],
        "b_peaks": [(450, 18, 1.0)],
        "fwd_threshold": "0.0",
        "fwd_linear": "1.0 1.0 0.0 0.0",
        "fwd_gamma": "2.2 1.0 1.0 0.0 0.0",
        "inv_threshold": "0.0",
        "inv_linear": "1.0 1.0 0.00000000 0.00000000",
        "inv_gamma": "0.454545454545455 1.0 1.0 0.0 0.0",
    },
]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def fmt_spectral(values: list[float]) -> str:
    """Format 401 values as space-separated on one line with 16 decimal places."""
    return " ".join(f"{v:.16f}" for v in values)


def fmt_observer(values: list[float]) -> str:
    """Format observer function row (6-digit precision like template)."""
    return " ".join(f"{v:.6f}" for v in values)


def fmt_d65(values: list[float]) -> str:
    """Format D65 illuminant SPD (6-digit precision like template)."""
    return " ".join(f"{v:.6f}" for v in values)


# ---------------------------------------------------------------------------
# XML generation
# ---------------------------------------------------------------------------

def generate_xml(profile: dict) -> str:
    r_spec = make_spectrum(profile["r_peaks"])
    g_spec = make_spectrum(profile["g_peaks"])
    b_spec = make_spectrum(profile["b_peaks"])
    white = [r + g + b for r, g, b in zip(r_spec, g_spec, b_spec)]

    white_str = fmt_spectral(white)
    r_str = fmt_spectral(r_spec)
    g_str = fmt_spectral(g_spec)
    b_str = fmt_spectral(b_spec)
    swpt_str = white_str

    xbar_str = fmt_observer(XBAR)
    ybar_str = fmt_observer(YBAR)
    zbar_str = fmt_observer(ZBAR)
    d65_str = fmt_d65(D65_SPD)

    fwd_t = profile["fwd_threshold"]
    fwd_l = profile["fwd_linear"]
    fwd_g = profile["fwd_gamma"]
    inv_t = profile["inv_threshold"]
    inv_l = profile["inv_linear"]
    inv_g = profile["inv_gamma"]
    desc = profile["desc"]

    # Build the segmented curve block for A2B1 (forward, 3 identical curves)
    fwd_curve = ""
    for _ in range(3):
        fwd_curve += f"""          <SegmentedCurve>
            <FormulaSegment Start="-infinity" End="{fwd_t}" FunctionType="0">
              {fwd_l}
            </FormulaSegment>
            <FormulaSegment Start="{fwd_t}" End="+infinity" FunctionType="3">
              {fwd_g}
            </FormulaSegment>
          </SegmentedCurve>
"""

    # Build the segmented curve block for B2A1 (inverse, 3 identical curves)
    inv_curve = ""
    for _ in range(3):
        inv_curve += f"""          <SegmentedCurve>
            <FormulaSegment Start="-infinity" End="{inv_t}" FunctionType="0">
              {inv_l}
            </FormulaSegment>
            <FormulaSegment Start="{inv_t}" End="+infinity" FunctionType="3">
              {inv_g}
            </FormulaSegment>
          </SegmentedCurve>
"""

    # NOTE: The trailing dot in IlluminantSPD start="380.00000000." is from
    # the original Rec2020rgbSpectral.xml template and MUST be preserved.
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<IccProfile>
  <Header>
    <PreferredCMMType></PreferredCMMType>
    <ProfileVersion>5.00</ProfileVersion>
    <ProfileDeviceClass>mntr</ProfileDeviceClass>
    <DataColourSpace>RGB </DataColourSpace>
    <PCS>XYZ </PCS>
    <CreationDateTime>now</CreationDateTime>
    <ProfileFlags EmbeddedInFile="true" UseWithEmbeddedDataOnly="false"/>
    <DeviceAttributes ReflectiveOrTransparency="reflective" GlossyOrMatte="glossy" MediaPolarity="positive" MediaColour="colour"/>
    <RenderingIntent>Relative Colorimetric</RenderingIntent>
    <PCSIlluminant>
      <XYZNumber X="0.9504222269" Y="1.0000000000" Z="1.0884541014"/>
    </PCSIlluminant>
    <ProfileCreator></ProfileCreator>
    <ProfileID>1</ProfileID>
  </Header>
  <Tags>
    <multiLocalizedUnicodeType>
      <TagSignature>desc</TagSignature>
      <LocalizedText LanguageCountry="enUS"><![CDATA[{desc}]]></LocalizedText>
    </multiLocalizedUnicodeType>
    <multiProcessElementType>
      <TagSignature>A2B1</TagSignature>
      <MultiProcessElements InputChannels="3" OutputChannels="3">
        <CurveSetElement InputChannels="3" OutputChannels="3">
{fwd_curve.rstrip()}
        </CurveSetElement>
        <EmissionMatrixElement InputChannels="3" OutputChannels="3">
          <Wavelengths start="380.00000000" end="780.00000000" steps="401"/>
          <WhiteData>
\t\t\t{white_str}
          </WhiteData>
          <MatrixData>
\t\t\t {r_str}
\t\t\t {g_str}
\t\t\t {b_str}
          </MatrixData>
        </EmissionMatrixElement>
      </MultiProcessElements>
    </multiProcessElementType>
    <multiProcessElementType>
      <TagSignature>B2A1</TagSignature>
      <MultiProcessElements InputChannels="3" OutputChannels="3">
        <InvEmissionMatrixElement InputChannels="3" OutputChannels="3">
          <Wavelengths start="380.00000000" end="780.00000000" steps="401"/>
          <WhiteData>
\t\t\t{white_str}
          </WhiteData>
          <MatrixData>
\t\t\t {r_str}
\t\t\t {g_str}
\t\t\t {b_str}
          </MatrixData>
        </InvEmissionMatrixElement>
        <CurveSetElement InputChannels="3" OutputChannels="3">
{inv_curve.rstrip()}
        </CurveSetElement>
      </MultiProcessElements>
    </multiProcessElementType>
    <multiProcessElementType>
      <TagSignature>c2sp</TagSignature>
      <MultiProcessElements InputChannels="3" OutputChannels="3">
        <MatrixElement InputChannels="3" OutputChannels="3">
          <MatrixData>
\t\t\t 1.1366412045848941 -0.0501909582786398 -0.0604664809307952
\t\t\t 0.0982474200827109 0.9346503106108431 -0.0257492184157053
\t\t\t -0.0342778407589584 0.0382994689628730 0.7522234528995555
          </MatrixData>
        </MatrixElement>
      </MultiProcessElements>
    </multiProcessElementType>
    <multiProcessElementType>
      <TagSignature>s2cp</TagSignature>
      <MultiProcessElements InputChannels="3" OutputChannels="3">
        <MatrixElement InputChannels="3" OutputChannels="3">
          <MatrixData>
\t\t\t 0.8781388144202196 0.0442017672036552 0.0721010819667443
\t\t\t -0.0910769479407390 1.0638357807880376 0.0290948617165519
\t\t\t 0.0446528236475119 -0.0521509987214560 1.3311963988799269
          </MatrixData>
        </MatrixElement>
      </MultiProcessElements>
    </multiProcessElementType>
    <spectralViewingConditionsType>
      <TagSignature>svcn</TagSignature>
      <StdObserver>CIE 1931 (two degree) standard observer</StdObserver>
      <IlluminantXYZ X="0.9504222269" Y="1.0000000000" Z="1.0884541014"/>
      <ObserverFuncs start="380.00000000" end="780.00000000" steps="401">
\t\t {xbar_str}
\t\t {ybar_str}
\t\t {zbar_str}
      </ObserverFuncs>
      <StdIlluminant>D65</StdIlluminant>
      <ColorTemperature>6500.00000000</ColorTemperature>
      <IlluminantSPD start="380.00000000." end="780.00000000" steps="401">
\t\t{d65_str}
      </IlluminantSPD>
      <SurroundXYZ X="0.9504222269" Y="1.0000000000" Z="1.0884541014"/>
    </spectralViewingConditionsType>
    <XYZType>
      <TagSignature>wtpt</TagSignature>
      <XYZNumber X="0.9504222269" Y="1.0000000000" Z="1.0884541014"/>
    </XYZType>
    <spectralDataInfoType>
      <TagSignature>sdin</TagSignature>
      <SpectralSpace>es0191</SpectralSpace>
      <SpectralRange>
        <Wavelengths start="380.000000" end="780.000000" steps="401"/>
      </SpectralRange>
    </spectralDataInfoType>
    <float16NumberType>
      <TagSignature>swpt</TagSignature>
      <Data>
\t\t{swpt_str}
      </Data>
    </float16NumberType>
    <multiLocalizedUnicodeType>
      <TagSignature>cprt</TagSignature>
      <LocalizedText LanguageCountry="enUS"><![CDATA[Copyright ICC Security Research]]></LocalizedText>
    </multiLocalizedUnicodeType>
  </Tags>
</IccProfile>"""
    return xml


# ---------------------------------------------------------------------------
# Build & verify
# ---------------------------------------------------------------------------

def find_iccdev(script_dir: Path) -> Path:
    """Auto-detect iccDEV directory relative to the script location."""
    # Script is at .github/scripts/ → repo root is ../../
    repo_root = script_dir.parent.parent
    candidate = repo_root / "iccDEV"
    if candidate.is_dir():
        return candidate
    # Try cfl/iccDEV as fallback
    candidate2 = repo_root / "cfl" / "iccDEV"
    if candidate2.is_dir():
        return candidate2
    return candidate  # return even if missing — caller will check


def find_observer_profile(iccdev_dir: Path) -> Path | None:
    """Find a v5 observer PCC profile for iccV5DspObsToV4Dsp verification."""
    candidates = [
        iccdev_dir / "Testing" / "PCC" / "XYZ_int-D65_2deg-MAT.icc",
        iccdev_dir / "Testing" / "Fuzzing" / "seeds" / "icc" / "XYZ_int-D65_2deg-MAT.icc",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def run_tool(cmd: list[str], env: dict, label: str) -> bool:
    """Run an iccDEV tool with ASAN options and LD_LIBRARY_PATH."""
    try:
        result = subprocess.run(
            cmd, env=env, capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  [{label}] FAILED (exit {result.returncode})")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[:5]:
                    print(f"    stderr: {line}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"  [{label}] TIMEOUT (60s)")
        return False
    except FileNotFoundError:
        print(f"  [{label}] Tool not found: {cmd[0]}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate ICC v5 spectral display profiles for fuzzer seeds"
    )
    parser.add_argument(
        "--output-dir",
        default="/tmp/spectral-profiles",
        help="Directory for generated XML and ICC files (default: /tmp/spectral-profiles)",
    )
    parser.add_argument(
        "--iccdev-dir",
        default=None,
        help="Path to iccDEV checkout (auto-detected if not specified)",
    )
    parser.add_argument(
        "--copy-to-test-profiles",
        action="store_true",
        help="Copy verified ICC files to test-profiles/",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.iccdev_dir:
        iccdev_dir = Path(args.iccdev_dir)
    else:
        iccdev_dir = find_iccdev(script_dir)

    # Locate tools (binary names are lowercase: iccFromXml, iccV5DspObsToV4Dsp)
    from_xml = iccdev_dir / "Build" / "Tools" / "IccFromXml" / "iccFromXml"
    v5_to_v4 = iccdev_dir / "Build" / "Tools" / "IccV5DspObsToV4Dsp" / "iccV5DspObsToV4Dsp"

    tools_ok = True
    if not from_xml.exists():
        print(f"WARNING: IccFromXml not found at {from_xml}")
        tools_ok = False
    if not v5_to_v4.exists():
        print(f"WARNING: IccV5DspObsToV4Dsp not found at {v5_to_v4}")
        tools_ok = False

    observer_icc = find_observer_profile(iccdev_dir)
    if not observer_icc:
        print("WARNING: No observer PCC profile found — V5→V4 verification will be skipped")

    if not tools_ok:
        print("  Tools not built — will generate XML only (no compilation/verification)")

    # Environment for running iccDEV tools
    tool_env = os.environ.copy()
    tool_env["LD_LIBRARY_PATH"] = (
        f"{iccdev_dir / 'Build' / 'IccProfLib'}:"
        f"{iccdev_dir / 'Build' / 'IccXML'}"
    )
    tool_env["ASAN_OPTIONS"] = "detect_leaks=0,halt_on_error=0"
    tool_env["UBSAN_OPTIONS"] = "halt_on_error=0,print_stacktrace=1"

    test_profiles_dir = repo_root / "test-profiles"

    generated = []
    compiled = []
    verified = []

    print(f"Generating {len(PROFILES)} ICC v5 spectral display profiles...")
    print(f"  Output: {output_dir}")
    print()

    for prof in PROFILES:
        name = prof["name"]
        xml_path = output_dir / f"{name}.xml"
        icc_path = output_dir / f"{name}.icc"
        v4_path = output_dir / f"{name}_v4.icc"

        # 1. Generate XML
        xml_content = generate_xml(prof)
        xml_path.write_text(xml_content, encoding="utf-8")
        generated.append(name)
        print(f"  [XML] {name}.xml ({xml_path.stat().st_size:,} bytes)")

        if not tools_ok:
            continue

        # 2. Compile XML → ICC via IccFromXml
        if run_tool(
            [str(from_xml), str(xml_path), str(icc_path)],
            tool_env,
            "IccFromXml",
        ):
            compiled.append(name)
            sz = icc_path.stat().st_size
            print(f"  [ICC] {name}.icc ({sz:,} bytes)")

            # 3. Verify via IccV5DspObsToV4Dsp (needs observer PCC profile)
            if observer_icc and run_tool(
                [str(v5_to_v4), str(icc_path), str(observer_icc), str(v4_path)],
                tool_env,
                "V5→V4",
            ):
                verified.append(name)
                v4_sz = v4_path.stat().st_size
                print(f"  [V4]  {name}_v4.icc ({v4_sz:,} bytes) — verified OK")
            elif not observer_icc:
                print(f"  [V4]  {name} — skipped (no observer profile)")
            else:
                print(f"  [V4]  {name} — V5→V4 conversion failed (profile still usable as v5 seed)")
        else:
            print(f"  [ICC] {name} — compilation failed")

        print()

    # 4. Copy verified files to test-profiles/ if requested
    if args.copy_to_test_profiles and compiled:
        test_profiles_dir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for name in compiled:
            src = output_dir / f"{name}.icc"
            dst = test_profiles_dir / f"{name}.icc"
            if src.exists():
                import shutil
                shutil.copy2(src, dst)
                copied += 1
                print(f"  [COPY] {name}.icc → test-profiles/")
        print(f"\n  Copied {copied} profiles to {test_profiles_dir}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  XML generated:  {len(generated)}/{len(PROFILES)}")
    print(f"  ICC compiled:   {len(compiled)}/{len(PROFILES)}")
    print(f"  V5→V4 verified: {len(verified)}/{len(PROFILES)}")

    if compiled:
        print(f"\n  ICC files in: {output_dir}")
        print("  Seed into CFL corpora:")
        print(f"    cp {output_dir}/*.icc cfl/corpus-icc_v5dspobs_fuzzer/")
        print(f"    cp {output_dir}/*.icc cfl/corpus-icc_spectral_fuzzer/")
        print(f"    cp {output_dir}/*.icc cfl/corpus-icc_profile_fuzzer/")

    if not tools_ok:
        print("\n  NOTE: iccDEV tools not found — only XML was generated.")
        print(f"  Build iccDEV first: cd {iccdev_dir} && mkdir -p Build && cd Build && cmake Cmake && make -j$(nproc)")
        return 1 if not generated else 0

    return 0 if compiled else 1


if __name__ == "__main__":
    sys.exit(main())

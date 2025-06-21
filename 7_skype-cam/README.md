Skype uses SILK as its audio codec, which supports discontinuous transmission. In SILK, bitrate is dropped to 0
during periods of silence (+ occasional "comfort packets" according to some docs). When the child is asleep,
provided the surroundings aren't constantly picked up on the microphone, you'd expect to see less traffic. When they
awake & make child noises -> more traffic.

Skype uses H.264/AVC for video encoding, which sends P-frames in addition to regular video frames. P-frames encode
the difference from reference full frames. As I understand, video with more "movement" would contain larger P-frames.
H.264/AVC also seems to be able to adjust bitrate to meet demand in 15-20 frames (https://ieeexplore.ieee.org/document/6264298).

I expect the child woke up between 12:56 - 12:58 based primarily on switch ports 2 & 3.

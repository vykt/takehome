// javascript is a mistake

function swap_end(num) {

    var components = [0,0,0,0];
    components[0] = num & 0xff000000;
    components[1] = num & 0x00ff0000;
    components[2] = num & 0x0000ff00;
    components[3] = num & 0x000000ff;

    var swapped = 0;
    swapped = swapped | (components[0] >>> 24);
    swapped = swapped | (components[1] >>> 8);
    swapped = swapped | (components[2] << 8);
    swapped = (swapped | (components[3] << 24 >>> 0)) >>> 0;
    
    return swapped;
}

function main() {

    tests = [0xff, 0x1, 0x1337, 0x15abfe87, 0xf0e0d0c0];

    for (let i = 0; i < 5; i++) {
        swapped = swap_end(tests[i]);
        console.log("original: ", tests[i].toString(16), " | swapped: ", swapped.toString(16));
    }
}

main();


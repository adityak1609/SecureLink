"""Generate valid, non-sensitive media fixtures; decode them before use."""
import argparse
import json
import math
from pathlib import Path
import struct
import subprocess
import wave

from PIL import Image, ImageDraw
import imageio_ffmpeg

from securelink.storage import file_hash


def generate(directory='sample_data/fixtures'):
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    (root / 'transaction.txt').write_text(json.dumps({'action':'transfer', 'source':'DEMO_A',
        'destination':'DEMO_B', 'amount_paise':12500}), encoding='utf-8')
    image = Image.new('RGB', (640, 360), '#e9f0fa')
    draw = ImageDraw.Draw(image)
    draw.rectangle((30,30,610,330), outline='#134a8e', width=4)
    draw.text((65,150), 'SecureLink - synthetic identity image - no personal data', fill='#134a8e')
    image.save(root / 'identity.png')
    image.save(root / 'identity.jpg')
    with wave.open(str(root / 'audio.wav'), 'wb') as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16000)
        output.writeframes(b''.join(struct.pack('<h', int(8000*math.sin(2*math.pi*440*t/16000))) for t in range(32000)))
    ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
    subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-y','-i',str(root/'audio.wav'),str(root/'audio.mp3')],check=True)
    subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-y','-f','lavfi','-i',
                    'testsrc2=size=640x360:rate=24','-t','3','-c:v','libx264','-pix_fmt','yuv420p',
                    '-movflags','+faststart',str(root/'video.mp4')],check=True)
    records = []
    for path in sorted(root.iterdir()):
        if path.suffix == '.json':
            continue
        if path.suffix in ('.png','.jpg'):
            with Image.open(path) as check:
                check.verify()
        elif path.suffix in ('.wav','.mp3','.mp4'):
            subprocess.run([ffmpeg,'-hide_banner','-loglevel','error','-xerror','-i',str(path),'-f','null','-'],check=True)
        records.append({'name':path.name,'size':path.stat().st_size,'sha256':file_hash(path),'validated':True})
    (root/'manifest.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
    return records

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--directory',default='sample_data/fixtures')
    print(json.dumps(generate(p.parse_args().directory),indent=2))

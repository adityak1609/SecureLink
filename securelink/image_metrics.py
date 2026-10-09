"""Bounded decoded-image measurements; fidelity is not encryption strength."""
import math
import warnings
from PIL import Image, ImageChops, ImageStat

MAX_METRIC_PIXELS=4_000_000


def image_metrics(source, received=None):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',Image.DecompressionBombWarning)
            with Image.open(source) as original:
                result={'status':'measured','source':{
                    'width':original.width,'height':original.height,'format':original.format,
                    'mode':original.mode,'channels':len(original.getbands()),
                    'encoded_bytes':source.stat().st_size},
                    'scope':'First decoded frame converted to 8-bit RGBA; pixel comparison measures transfer fidelity, not encryption strength.'}
                if received is None:
                    result['comparison']='Receive this image to measure fidelity.'
                    return result
                with Image.open(received) as copy:
                    result['received']={'width':copy.width,'height':copy.height,'format':copy.format,
                        'mode':copy.mode,'channels':len(copy.getbands()),'encoded_bytes':received.stat().st_size}
                    if original.size!=copy.size:
                        result['comparison']='Image dimensions differ; MSE/PSNR not computed.'
                        return result
                    if original.width*original.height>MAX_METRIC_PIXELS:
                        result['comparison']='Pixel comparison skipped above 4 million pixels; byte-hash verification still applies.'
                        return result
                    difference=ImageChops.difference(original.convert('RGBA'),copy.convert('RGBA'))
                    mse=sum(ImageStat.Stat(difference).sum2)/(original.width*original.height*4)
                    result.update(comparison='Decoded RGBA pixels compared',pixels_equal=mse==0,
                        mse=mse,psnr_db=None if mse==0 else 10*math.log10(255**2/mse),
                        psnr='Infinity (identical pixels)' if mse==0 else 'Finite')
                    return result
    except (OSError,ValueError,Image.DecompressionBombWarning,Image.DecompressionBombError):
        return {'status':'unavailable','comparison':'Image could not be safely decoded for optional metrics; transfer verification uses SHA-256.'}

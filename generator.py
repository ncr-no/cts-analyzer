import os
import run_mulval
import output_postprocessing


def generate_kcag():
    """
    This procedure runs MulVAL to create an attack graph. The attack graph is then post-processed to create KCAG.
    """
    if not os.path.exists("/tmp/mulval_dir"):
        os.mkdir("/tmp/mulval_dir")
    run_mulval.run_mulval("conf.ini")
    output_postprocessing.create_and_postprocess_kcag()


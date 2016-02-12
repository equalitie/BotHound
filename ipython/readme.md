
# How to run Ipython notebook

1. Run Jupyter on server from the folder with the ipynb:

jupyter notebook --no-browser --port=8889

2. Run SSH tunnel on your local machine

ssh -N -L 8889:127.0.0.1:8889 user@server -p 2223

3. Open http://127.0.0.1:8889

import itertools,time
MASK=0xffff
S=((0,1,8),(14,5,0),(9,12,8),(14,5,0),(0,1,8),(8,9,0))
BASE=[0x243F,0x6A88,0x85A3,0x08D3,0x1319,0x8A2E,0x0370,0x7344]
def rr(x,k): return ((x>>k)|(x<<(16-k)))&MASK if k else x
def ar(L,R,a,b,g): return ((rr(L,a)&rr(L,b))^rr(L,g)^R)&MASK,L
def mandrx(a):
 a=[row[:] for row in a]
 for r in S:
  for y in range(6):
   for x in range(8): a[y][x][0],a[y][x][1]=ar(a[y][x][0],a[y][x][1],*r)
 return a
def mandrx_inv(a):
 a=[row[:] for row in a]
 for y in range(6):
  for x in range(8):
   L,R=a[y][x][0],a[y][x][1]
   for r in reversed(S):
    L,R=ar(R,L,*r)
   a[y][x][0],a[y][x][1]=L,R
 return a
def cross(a):
 b=[[cell[:] for cell in row] for row in a]
 for x in range(8):
  for z in (0,1):
   v=[a[y][x][z] for y in range(6)]
   b[0][x][z]=v[0]^v[1]^v[4];b[1][x][z]=v[1]^v[2]^v[5]
   b[2][x][z]=v[0]^v[2]^v[3];b[3][x][z]=v[1]^v[3]^v[4]
   b[4][x][z]=v[2]^v[4]^v[5];b[5][x][z]=v[0]^v[3]^v[5]
 return b
def swap(a):
 b=[[cell[:] for cell in row] for row in a]
 for y in (3,4,5):
  for x in range(8): b[y][x][0],b[y][x][1]=a[y][x][1],a[y][x][0]
 return b
def mixcols(a):
 b=[[cell[:] for cell in row] for row in a]
 for x in range(8):
  for z in (0,1):
   v0,v1,v2=[a[y][x][z] for y in (0,1,2)]
   b[0][x][z]=v1^v2; b[1][x][z]=v0^v2; b[2][x][z]=v0^v1^v2
   v0,v1,v2=[a[y][x][z] for y in (3,4,5)]
   b[3][x][z]=v0^v2; b[4][x][z]=v1^v2; b[5][x][z]=v0^v1^v2
 return b
def shift(a):
 b=[[[0,0] for x in range(8)] for y in range(6)]
 for y in range(6):
  for x in range(8):
   b[y][(x-y)%8][0]=a[y][x][0]
   b[y][(x+y)%8][1]=a[y][x][1]
 return b
def rnd(a,rc):
 a=cross(a); a=swap(a); a=mandrx(a); a=cross(a); a=swap(a); a=mixcols(a); a=shift(a)
 for x in range(8): a[0][x][0]^=rc
 return a
def iround(a,rc):
 b=[[cell[:] for cell in row] for row in a]
 for x in range(8): b[0][x][0]^=rc
 b=mixcols(b)
 for y in range(6):
  for x in range(8): b[y][x][0],b[y][x][1]=b[y][x][1],b[y][x][0]
 b=shift(b); b=mixcols(b)
 for y in range(6):
  for x in range(8): b[y][x][0],b[y][x][1]=b[y][x][1],b[y][x][0]
 b=swap(b); b=cross(b)
 for y in range(6):
  for x in range(8): b[y][x][0],b[y][x][1]=b[y][x][1],b[y][x][0]
 b=mandrx_inv(b); b=swap(b); b=cross(b)
 return b
def cube_f(a):
 x=[[cell[:] for cell in row] for row in a]
 y=[[cell[:] for cell in row] for row in a]
 for i in range(9):
  rc=BASE[i%8]^i; x=rnd(x,rc); y=iround(y,rc)
 for yy in range(6):
  for xx in range(8):
   for z in range(2): x[yy][xx][z]^=y[yy][xx][z]
 return x

def make_maps():
 dims={'x':8,'y':6,'z':2}
 orders=list(itertools.permutations('xyz'))
 for order in orders:
  for revparts in range(8):
   def flat(c,order=order,revparts=revparts):
    n=0
    for i,name in enumerate(order):
     v=c[name]
     if revparts>>i&1:v=dims[name]-1-v
     n=n*dims[name]+v
    return n
   yield order,revparts,flat
def parse_hex(s):return bytes.fromhex(s)
def bits_to_cells(bits,flat,endian):
 a=[[[0,0] for x in range(8)] for y in range(6)]
 for idx,bit in enumerate(bits):
  if idx>=1536:break
  n=idx//16; off=idx%16
  z=n%2; n//=2; y=n%6;n//=6;x=n%8
  # n is flat coord; need invert flat impossible general. Instead direct enumerate coordinate list.
 # handled outside
 return a
# construct coordinate list in flatten order
D={'x':8,'y':6,'z':2}
def coords(order,revparts):
 out=[]
 for xx in range(8):
  for yy in range(6):
   for zz in range(2):
    c={'x':xx,'y':yy,'z':zz}
    if any((revparts>>i)&1 for i,_ in enumerate(order)):
     c={k:(D[k]-1-v if (revparts>>i)&1 else v) for i,k in enumerate(order) for v in [c[k]]}
    out.append(c)
 # sort by flatten value
 def val(c):
  n=0
  for k in order:n=n*D[k]+c[k]
  return n
 return sorted(out,key=val)
def msg_bits(hexs):
 bs=bytes.fromhex(hexs)
 return [(byte>>(7-i))&1 for byte in bs for i in range(8)]
def hash512(hexs,order,revs,endian,ratetail=False,outrev=False):
 cs=coords(order,revs); a=[[[0,0] for x in range(8)] for y in range(6)]
 bits=msg_bits(hexs); bits.append(1)
 while len(bits)%960:bits.append(0)
 bits.append(1)
 # for 16-bit msg r960: appended 1, zeros, final 1; align last bit to block end
 # above while includes final? len=17 then 943 zeros ->960, then append ->961 wrong. fix if needed below
 if len(bits)!=960:
  bits=msg_bits(hexs)+[1]; bits += [0]*(959-len(bits)); bits += [1]
 # absorb blocks
 for bo in range(0,len(bits),960):
  block=bits[bo:bo+960]
  cells=cs[-60:] if ratetail else cs[:60]
  for j,bit in enumerate(block):
   cellidx=j//16; bitoff=j%16
   c2=cells[cellidx]
   sh=(bitoff if endian=='lsb' else 15-bitoff)
   a[c2['y']][c2['x']][c2['z']]^=bit<<sh
  a=cube_f(a)
 out=[]; oc=cs[-512:] if outrev else cs[:512]
 cells_out=cs[-32:] if outrev else cs[:32]
 for j in range(512):
  ci=j//16; c=cells_out[ci]; sh=(j%16 if endian=='lsb' else 15-j%16)
  out.append((a[c['y']][c['x']][c['z']]>>sh)&1)
 return bytes(sum(out[i+j]<<(7-j) for j in range(8)) for i in range(0,512,8)).hex().upper()
want='C6ADAAFAC38E7BDAA6EAF589376AACCE00D7DCA0B5AC9F6282C6082637B0196B42AB3C3C6D8F2DA9D43E7B81FC17C3715CE5DDB7B0EA988AAC782925336B3FF7'
for order in itertools.permutations('xyz'):
 for revs in range(8):
  for endian in ('msb','lsb'):
   try: got=hash512('5D9B',order,revs,endian)
   except Exception as e:
    print('ERR',order,revs,e);raise
   print(order,revs,endian,got[:16], 'MATCH' if got==want else '')

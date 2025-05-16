# Branch profiling

I profiled 100 random branches from project codenet in order to see commonly used constants/inequalities used for branches. Here are the results.

I noticed that pointer and struct types do not appear often; this is probably due to the simple nature of the codenet programs, but would appear more often in open-source programs.

## int type

### value is negative

* `s360381106.c`: if_statement: (C<=0)
* `s942970601.c`: if_statement: (s < 0)

### value is positive

* `s837780109.c`: if_statement: (cnt1 > 0)
* `s837780109.c`: if_statement: (cnt2 > 0)
* `s837780109.c`: if_statement: (cnt3 > 0)

### value < upper bound

* `s101296823.c`: for_statement: i<h

### value == 0 as arithmetic result

* `s059498899.c`: if_statement: (H == 0)

### value == 0 as error code from function

Value returned from function in C is commonly 0 or nonzero
* `s047122283.c`: if_statement: (strcmp(W,T)==0)
* `s499705513.c`: for_statement: scanf("%d %d %d %d %d",&N,&A,&B,&C,&X)&&(N||A||B||C||X)

### value is equal, less-than, or greater-than a problem-dependant value

This was the most common case.

* `s000369988.c`: for_statement: j<10
* `s000552118.c`: for_statement: j<=9
* `s837780109.c`: if_statement: (x == 2)

* `s059564662.c`: if_statement: (65536<(double)(K/i)&&(double)(K/i)<=131072)

* `s360381106.c`: if_statement: (A<0 || A>100)

## float type

### value is problem-dependent

This was the most common case for float types, too.

* `s837780109.c`: if_statement: (ans != -1.0)

### value == zero (may not actually be super common, only seen once)
* `s168530156.c`: if_statement: (x == -0.0)

## "boolean" type, represented by integer in C

### infinite while loop

* `s000997878.c`: while_statement: (1)
* `s047122283.c`: while_statement: (1)

### counter value i > 0 implicitly

* `s005285403.c`: while_statement: (i--)
* `s001916794.c`: while_statement: (x)
* `s812682047.c`: for_statement: k--

### result of boolean operation is 1 or 0

* `s000997878.c`: for_statement: j<n && j<i*20+20
* `s003356722.c`: if_statement: (!b)

## char type

### almost always seems problem-dependent

We could probably look for some commonly-used characters such as whitespace, hash, 'A', 'Z', etc.
* `s220489177.c` if_statement: (a[i][j]: == '#')
* `s949740278.c`: if_statement: (cha >= 'A'&&cha <= 'Z')
* `s929679645.c`: do_statement: (c >= '0')
* `s929679645.c`: if_statement: (c == '-')

* `s444652609.c`: if_statement: (s=="/")
* `s444652609.c`: if_statement: (s=="*")
* `s444652609.c`: if_statement: (s=="-")
* `s444652609.c`: if_statement: (s=="+")

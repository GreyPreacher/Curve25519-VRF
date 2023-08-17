# Curve25519-VRF
This is the Python version of VRF algorithms written by Alvin Zhang on the Elliptical Curve Curve25519.

# Paper
Tsz Hon Yuen, Shimin Pan, Shen Huang, Xiaoting Zhang. ”Practical Verifiable Random Function with RKA Security” in _Australasian Conference on Information Security and Privacy_. ACISP 2023. LNCS, vol 13915, pp. 503-522. Springer, Cham (2023). https://doi.org/10.1007/978-3-031-35486-1_22

# Algorithms
<pre class="pseudocode">
% This quicksort algorithm is extracted from Chapter 7, Introduction to Algorithms (3rd edition)
\begin{algorithm}
\caption{Quicksort}
\begin{algorithmic}
\PROCEDURE{Quicksort}{$A, p, r$}
    \IF{$p < r$} 
        \STATE $q = $ \CALL{Partition}{$A, p, r$}
        \STATE \CALL{Quicksort}{$A, p, q - 1$}
        \STATE \CALL{Quicksort}{$A, q + 1, r$}
    \ENDIF
\ENDPROCEDURE
\PROCEDURE{Partition}{$A, p, r$}
    \STATE $x = A[r]$
    \STATE $i = p - 1$
    \FOR{$j = p$ \TO $r - 1$}
        \IF{$A[j] < x$}
            \STATE $i = i + 1$
            \STATE exchange
            $A[i]$ with $A[j]$
        \ENDIF
        \STATE exchange $A[i]$ with $A[r]$
    \ENDFOR
\ENDPROCEDURE
\end{algorithmic}
\end{algorithm}
</pre>

# Time
The algorithms needs about 42s to run for 1000 times of evaluation and verification.

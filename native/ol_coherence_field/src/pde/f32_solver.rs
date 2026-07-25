//! f32 Helmholtz solver — half the memory, ~2× the throughput for
//! "rough snapshot" use cases that don't need f64 precision.
//!
//! ## When to use
//!
//! The f64 solver is the production-quality default and matches the
//! `S_One` canonical theorem stack's numerical precision expectations.
//! The f32 path is for callers that need raw throughput more than
//! 6-decimal residuals — e.g., daemon snapshots fed back to the
//! BE-RAR scorer (where the downstream `nu(y)` mapping smears out
//! anything below ~1e-3 anyway).
//!
//! ## Trade-offs
//!
//! - **Memory**: 4 bytes per scalar instead of 8. Workspace at 50k
//!   peers drops from ~2 MB to ~1 MB.
//! - **Throughput**: ~2× on memory-bound matvec (AVX-256 lanes hold
//!   8× f32 vs 4× f64). Roughly 1.3-1.6× on the full solve once CG
//!   serial overhead is factored in.
//! - **Precision**: ~1e-7 machine epsilon vs ~2e-16. Convergence to
//!   any tolerance below ~1e-6 is unreliable; the tolerance check
//!   clamps to a sane minimum.
//!
//! ## Bridge to the f64 graph
//!
//! The `GraphLaplacian` stays f64 internally (correctness of the
//! algebra matters more than the solver's working precision). The
//! f32 path downcasts on read inside its CSR walk — no global
//! representation change required.

use super::{FieldError, GraphLaplacian, SolveResult};

/// Narrow a binary64 value to binary32 with IEEE-754 round-to-nearest,
/// ties-to-even semantics. This is the explicit equivalent of Rust's numeric
/// narrowing conversion, expressed in bits so overflow, subnormal values,
/// infinities, NaNs, and signed zero are handled deliberately.
#[inline]
fn f64_to_f32(value: f64) -> f32 {
    const F64_FRACTION_MASK: u64 = (1_u64 << 52) - 1;
    const F32_FRACTION_MASK: u64 = (1_u64 << 23) - 1;
    const F32_INFINITY_BITS: u32 = 0x7f80_0000;

    let bits = value.to_bits();
    let sign = if bits & (1_u64 << 63) == 0 {
        0
    } else {
        1_u32 << 31
    };
    let biased_exponent = (bits >> 52) & 0x7ff;
    let fraction = bits & F64_FRACTION_MASK;

    if biased_exponent == 0x7ff {
        if fraction == 0 {
            return f32::from_bits(sign | F32_INFINITY_BITS);
        }
        let payload = u32::try_from(fraction >> 29)
            .expect("the leading 23 binary64 payload bits fit binary32")
            | (1_u32 << 22);
        return f32::from_bits(sign | F32_INFINITY_BITS | payload);
    }
    if biased_exponent == 0 {
        // Every binary64 subnormal is far below half of binary32's minimum
        // subnormal, so it rounds to signed zero.
        return f32::from_bits(sign);
    }

    let exponent =
        i32::try_from(biased_exponent).expect("an 11-bit binary64 exponent always fits i32") - 1023;
    if exponent > 127 {
        return f32::from_bits(sign | F32_INFINITY_BITS);
    }

    let significand = (1_u64 << 52) | fraction;
    if exponent >= -126 {
        let mut rounded = round_shift_right_ties_even(significand, 29);
        let mut output_exponent = exponent + 127;
        if rounded == 1_u64 << 24 {
            rounded >>= 1;
            output_exponent += 1;
        }
        if output_exponent >= 255 {
            return f32::from_bits(sign | F32_INFINITY_BITS);
        }
        let exponent_bits = u32::try_from(output_exponent)
            .expect("a finite binary32 exponent is non-negative")
            << 23;
        let fraction_bits = u32::try_from(rounded & F32_FRACTION_MASK)
            .expect("a 23-bit binary32 fraction fits u32");
        return f32::from_bits(sign | exponent_bits | fraction_bits);
    }

    if exponent < -150 {
        return f32::from_bits(sign);
    }
    let shift =
        u32::try_from(-exponent - 97).expect("binary32 subnormal scaling shift is non-negative");
    let subnormal = round_shift_right_ties_even(significand, shift);
    let subnormal_bits =
        u32::try_from(subnormal).expect("a rounded binary32 subnormal significand fits u32");
    f32::from_bits(sign | subnormal_bits)
}

#[inline]
fn round_shift_right_ties_even(value: u64, shift: u32) -> u64 {
    if shift == 0 {
        return value;
    }
    if shift >= 64 {
        return 0;
    }
    let truncated = value >> shift;
    let remainder = value & ((1_u64 << shift) - 1);
    let halfway = 1_u64 << (shift - 1);
    let round_up = remainder > halfway || (remainder == halfway && truncated & 1 == 1);
    truncated + u64::from(round_up)
}

/// f32-flavoured CG config.
#[derive(Debug, Clone, Copy)]
pub struct CgConfigF32 {
    /// Max iterations.
    pub max_iter: usize,
    /// Relative tolerance. Clamped to ≥ 1e-6 internally because f32
    /// cannot meaningfully resolve below that.
    pub tolerance: f32,
}

impl Default for CgConfigF32 {
    fn default() -> Self {
        Self {
            max_iter: 2000,
            tolerance: 1e-5,
        }
    }
}

/// Pre-allocated f32 workspace.
#[derive(Debug)]
pub struct CgWorkspaceF32 {
    n: usize,
    pub(crate) x: Vec<f32>,
    pub(crate) r: Vec<f32>,
    pub(crate) z: Vec<f32>,
    pub(crate) p: Vec<f32>,
    pub(crate) ap: Vec<f32>,
}

impl CgWorkspaceF32 {
    /// Allocate workspace for `n` unknowns. Memory footprint:
    /// `5 × n × 4` bytes (vs 8 for the f64 path).
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            n,
            x: vec![0.0; n],
            r: vec![0.0; n],
            z: vec![0.0; n],
            p: vec![0.0; n],
            ap: vec![0.0; n],
        }
    }

    /// Resize the workspace if `n` changed.
    pub fn resize(&mut self, n: usize) {
        if self.n == n {
            return;
        }
        self.x.resize(n, 0.0);
        self.r.resize(n, 0.0);
        self.z.resize(n, 0.0);
        self.p.resize(n, 0.0);
        self.ap.resize(n, 0.0);
        self.n = n;
    }

    /// Zero the initial guess.
    pub fn zero_initial_guess(&mut self) {
        for xi in &mut self.x {
            *xi = 0.0;
        }
    }
}

/// f32 Helmholtz solver. Bundle of workspace + diag cache.
#[derive(Debug)]
pub struct HelmholtzSolverF32 {
    workspace: CgWorkspaceF32,
    diag: Vec<f32>,
}

impl HelmholtzSolverF32 {
    /// Allocate the solver.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            workspace: CgWorkspaceF32::new(n),
            diag: vec![0.0; n],
        }
    }

    /// Resize for a new graph size. Cheap on no-op.
    pub fn resize(&mut self, n: usize) {
        if self.workspace.n == n {
            return;
        }
        self.workspace.resize(n);
        self.diag.resize(n, 0.0);
    }

    /// Solve `(Γ · I + D · L) · δτ_c = S` in f32. The graph stays
    /// f64; we downcast on read.
    pub fn solve(
        &mut self,
        graph: &GraphLaplacian,
        d: f32,
        gamma: f32,
        source: &[f32],
        config: CgConfigF32,
    ) -> Result<SolveResultF32, FieldError> {
        let n = graph.n();
        if source.len() != n {
            return Err(FieldError::SourceLengthMismatch {
                source_len: source.len(),
                node_count: n,
            });
        }
        if d == 0.0 && gamma == 0.0 {
            return Err(FieldError::SingularOperator);
        }
        if d <= 0.0 || gamma < 0.0 {
            return Err(FieldError::NonPhysicalConstants {
                d: f64::from(d),
                gamma: f64::from(gamma),
            });
        }
        self.resize(n);
        // diag[i] = gamma + d * degree(i). Graph degrees are f64;
        // cast to f32 on read.
        for i in 0..n {
            self.diag[i] = gamma + d * f64_to_f32(graph.degree(i));
        }
        // Clamp tolerance — f32 can't resolve below ~1e-6 reliably.
        let tol = config.tolerance.max(1e-6_f32);
        let max_iter = config.max_iter;

        let CgWorkspaceF32 {
            n: _,
            x,
            r,
            z,
            p,
            ap,
        } = &mut self.workspace;

        // Always cold-start in f32 — warm-starting between solves
        // amplifies the precision loss across iterations.
        for v in x.iter_mut() {
            *v = 0.0;
        }
        r.copy_from_slice(source);

        // z = D^-1 r (Jacobi precond).
        for i in 0..n {
            let di = self.diag[i];
            z[i] = if di.abs() > 1e-30 { r[i] / di } else { r[i] };
        }
        p.copy_from_slice(z);

        let mut r_dot_z = dot_f32(r, z);
        let bnorm_sq = dot_f32(source, source).max(1e-30);
        let tol_sq = tol * tol;
        let mut iterations = 0;
        let mut r_norm_sq = dot_f32(r, r);
        let mut residual = (r_norm_sq / bnorm_sq).sqrt();
        let mut converged = r_norm_sq <= tol_sq * bnorm_sq;

        while !converged && iterations < max_iter {
            // ap = (gamma · I + d · L) · p
            //    = gamma · p + d · (L · p)
            matvec_f32(graph, p, ap);
            for i in 0..n {
                ap[i] = gamma * p[i] + d * ap[i];
            }
            let p_ap = dot_f32(p, ap);
            if p_ap.abs() < 1e-30 {
                break;
            }
            let alpha = r_dot_z / p_ap;
            let mut new_r_norm_sq = 0.0_f32;
            for i in 0..n {
                x[i] += alpha * p[i];
                let ri = r[i] - alpha * ap[i];
                r[i] = ri;
                new_r_norm_sq += ri * ri;
            }
            r_norm_sq = new_r_norm_sq;
            for i in 0..n {
                let di = self.diag[i];
                z[i] = if di.abs() > 1e-30 { r[i] / di } else { r[i] };
            }
            let r_dot_z_new = dot_f32(r, z);
            let beta = r_dot_z_new / r_dot_z.max(1e-30);
            for i in 0..n {
                p[i] = z[i] + beta * p[i];
            }
            r_dot_z = r_dot_z_new;
            iterations += 1;
            residual = (r_norm_sq / bnorm_sq).sqrt();
            converged = r_norm_sq <= tol_sq * bnorm_sq;
        }

        if !converged {
            return Err(FieldError::NotConverged {
                iterations,
                residual: f64::from(residual),
                tolerance: f64::from(tol),
            });
        }

        Ok(SolveResultF32 {
            field: x.clone(),
            residual,
            iterations,
            converged,
        })
    }

    /// Borrow the most-recent field.
    #[must_use]
    pub fn last_field(&self) -> &[f32] {
        &self.workspace.x
    }
}

/// f32 solve result.
#[derive(Debug, Clone)]
pub struct SolveResultF32 {
    /// Recovered field.
    pub field: Vec<f32>,
    /// Final relative residual.
    pub residual: f32,
    /// Iterations.
    pub iterations: usize,
    /// Converged?
    pub converged: bool,
}

impl SolveResultF32 {
    /// Upcast to f64 for callers that need the wider type downstream.
    #[must_use]
    pub fn to_f64(&self) -> SolveResult {
        SolveResult {
            field: self.field.iter().map(|&v| f64::from(v)).collect(),
            residual: f64::from(self.residual),
            iterations: self.iterations,
            converged: self.converged,
        }
    }
}

fn dot_f32(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    // Same 4-way unroll trick as the f64 path; auto-vec emits f32×8
    // FMAs on AVX2.
    let n = a.len();
    let blocks = n / 4;
    let mut s0 = 0.0_f32;
    let mut s1 = 0.0_f32;
    let mut s2 = 0.0_f32;
    let mut s3 = 0.0_f32;
    for k in 0..blocks {
        let i = k * 4;
        s0 += a[i] * b[i];
        s1 += a[i + 1] * b[i + 1];
        s2 += a[i + 2] * b[i + 2];
        s3 += a[i + 3] * b[i + 3];
    }
    let mut tail = (s0 + s1) + (s2 + s3);
    for i in (blocks * 4)..n {
        tail += a[i] * b[i];
    }
    tail
}

/// f32 matvec: `y = L · x`. The graph stores f64 weights + indices;
/// we downcast weights to f32 on the fly and read x[col] directly.
/// Slightly less cache-efficient than a pure-f32 CSR would be (the
/// f64 weight read uses an 8-byte path), but the simplicity outweighs
/// the few-percent loss vs maintaining a parallel f32 CSR.
fn matvec_f32(graph: &GraphLaplacian, x: &[f32], y: &mut [f32]) {
    debug_assert_eq!(x.len(), graph.n());
    debug_assert_eq!(y.len(), graph.n());
    for i in 0..graph.n() {
        let mut acc = f64_to_f32(graph.degree(i)) * x[i];
        for &(j, w) in graph.neighbors(i) {
            acc -= f64_to_f32(w) * x[j];
        }
        y[i] = acc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f64_to_f32_covers_ieee_boundaries() {
        assert_eq!(f64_to_f32(0.0).to_bits(), 0);
        assert_eq!(f64_to_f32(-0.0).to_bits(), 1_u32 << 31);
        assert_eq!(f64_to_f32(1.0).to_bits(), 0x3f80_0000);
        assert_eq!(f64_to_f32(-2.5).to_bits(), 0xc020_0000);
        assert_eq!(f64_to_f32(f64::MAX).to_bits(), f32::INFINITY.to_bits());
        assert_eq!(
            f64_to_f32(f64::NEG_INFINITY).to_bits(),
            f32::NEG_INFINITY.to_bits()
        );
        assert!(f64_to_f32(f64::NAN).is_nan());

        let minimum_subnormal = f64::from(f32::from_bits(1));
        assert_eq!(f64_to_f32(minimum_subnormal).to_bits(), 1);
        assert_eq!(f64_to_f32(minimum_subnormal / 2.0).to_bits(), 0);
        assert_eq!(f64_to_f32(minimum_subnormal * 0.75).to_bits(), 1);

        let halfway_at_one = 1.0 + 2.0_f64.powi(-24);
        assert_eq!(f64_to_f32(halfway_at_one).to_bits(), 1.0_f32.to_bits());
        assert_eq!(
            f64_to_f32(halfway_at_one + 2.0_f64.powi(-52)).to_bits(),
            1.0_f32.next_up().to_bits()
        );
    }

    #[test]
    fn f32_solver_recovers_known_solution_on_path_graph() {
        // 5-node path, point source at center. Expected field shape
        // is symmetric + monotonically decreasing outward — the same
        // qualitative behaviour as the f64 path. Numerical agreement
        // to ~1e-3 relative is the f32 quality bar.
        let n = 5;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let mut s = vec![0.0_f32; n];
        s[2] = 1.0;
        let mut solver = HelmholtzSolverF32::new(n);
        let r = solver
            .solve(&g, 1.0, 0.5, &s, CgConfigF32::default())
            .unwrap();
        // Symmetry within f32 precision.
        assert!((r.field[0] - r.field[4]).abs() < 1e-4);
        assert!((r.field[1] - r.field[3]).abs() < 1e-4);
        // Monotonic outward.
        assert!(r.field[2] > r.field[1]);
        assert!(r.field[1] > r.field[0]);
    }

    #[test]
    fn f32_solver_agrees_with_f64_to_tolerance() {
        use super::super::{solve_helmholtz, CgConfig};
        let n = 32;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        for i in (0..n).step_by(5) {
            let j = (i + 11) % n;
            if i != j {
                let _ = g.add_edge(i, j, 0.5);
            }
        }
        let mut s32 = vec![0.0_f32; n];
        s32[n / 2] = 1.0;
        let s64: Vec<f64> = s32.iter().map(|&v| f64::from(v)).collect();
        let mut solver = HelmholtzSolverF32::new(n);
        let r32 = solver
            .solve(&g, 1.0, 0.5, &s32, CgConfigF32::default())
            .unwrap();
        let r64 = solve_helmholtz(
            &g,
            1.0,
            0.5,
            &s64,
            CgConfig {
                max_iter: 2000,
                tolerance: 1e-9,
            },
        )
        .unwrap();
        for i in 0..n {
            let a = f64::from(r32.field[i]);
            let b = r64.field[i];
            let rel = (a - b).abs() / b.abs().max(1e-9);
            assert!(
                rel < 5e-4,
                "f32 vs f64 diverged at node {i}: f32={a:.6}, f64={b:.6}, rel={rel:.3e}"
            );
        }
    }

    #[test]
    fn f32_to_f64_upcast_preserves_field() {
        let n = 4;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let s = vec![1.0_f32; n];
        let mut solver = HelmholtzSolverF32::new(n);
        let r = solver
            .solve(&g, 1.0, 0.5, &s, CgConfigF32::default())
            .unwrap();
        let upcast = r.to_f64();
        for i in 0..n {
            assert!((upcast.field[i] - f64::from(r.field[i])).abs() < 1e-12);
        }
    }

    #[test]
    fn f32_solver_rejects_source_length_mismatch() {
        let n = 4;
        let g = GraphLaplacian::new(n);
        let s = vec![1.0_f32; n + 1];
        let mut solver = HelmholtzSolverF32::new(n);
        let err = solver
            .solve(&g, 1.0, 0.5, &s, CgConfigF32::default())
            .unwrap_err();
        assert!(matches!(err, FieldError::SourceLengthMismatch { .. }));
    }

    #[test]
    fn f32_solver_rejects_non_physical_constants() {
        let n = 3;
        let g = GraphLaplacian::new(n);
        let s = vec![0.0_f32; n];
        let mut solver = HelmholtzSolverF32::new(n);
        assert!(matches!(
            solver
                .solve(&g, -1.0, 0.0, &s, CgConfigF32::default())
                .unwrap_err(),
            FieldError::NonPhysicalConstants { .. }
        ));
        assert!(matches!(
            solver
                .solve(&g, 0.0, 0.0, &s, CgConfigF32::default())
                .unwrap_err(),
            FieldError::SingularOperator
        ));
    }
}

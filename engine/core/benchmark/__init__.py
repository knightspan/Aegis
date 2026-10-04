"""The registered recovery benchmark, as a first-class part of the product.

* :mod:`~core.benchmark.manifest` - the sealed ground-truth manifest.
* :mod:`~core.benchmark.outputs` - output indexing and attribution, shared with
  the synthetic benchmark in ``testkit/benchmark.py``.
* :mod:`~core.benchmark.score` - the per-file scorer.
* :mod:`~core.benchmark.rule` - the registered 5/10 recall rule.
* :mod:`~core.benchmark.result` - the sealed, optionally signed, ledgered result.
* :mod:`~core.benchmark.stats` - aggregation that never mixes SYNTHETIC and
  PHYSICAL, and the only place that may say PHYSICALLY VALIDATED.
* :mod:`~core.benchmark.cli` - ``python -m core.benchmark``.

Nothing in this package imports testkit, opens a device, or touches the
network. Submodules are imported by name; importing the package itself loads
nothing, so ``collect_submodules`` in the PyInstaller spec sees every module.
"""

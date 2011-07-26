from supplement.assistant import infer

from .helpers import pytest_funcarg__project, do_assist

def test_calls_update(project):
    scope = project.create_scope('''
        def bar():
            pass

        def foo(arg):
            map(arg, bar())

        foo(int)
    ''')

    project.calldb.collect_calls(scope)
    assert len(project.calldb.calls[(None, 'foo')]) == 1

    scope = project.create_scope('''
        def bar():
            pass

        def foo(arg):
            map(arg, bar())
    ''')

    project.calldb.collect_calls(scope)
    assert len(project.calldb.calls[(None, 'foo')]) == 0

def test_calldb_must_provide_arguments_for_function(project):
    result = do_assist(project, '''
        def foo(arg):
            arg.a|

        foo([])
    ''')

    assert 'append' in result

def test_calldb_must_provide_arguments_for_constructor(project):
    result = do_assist(project, '''
        class Foo(object):
            def __init__(self, arg):
                self.arg = arg

        Foo([]).arg.a|
    ''')

    assert 'append' in result

def test_calldb_must_provide_arguments_for_methods(project):
    result = do_assist(project, '''
        class Foo(object):
            def foo(self, arg):
                arg.a|

        Foo().foo([])
    ''')

    assert 'append' in result

def test_calldb_for_imported_function(project):
    m = project.create_module('toimport', '''
        def foo(arg):
            pass
    ''')

    scope = project.create_scope('''
        from toimport import foo
        foo([])
    ''')

    project.calldb.collect_calls(scope)
    result = infer('arg', m.get_scope_at(2))
    assert 'append' in result
